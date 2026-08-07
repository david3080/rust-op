#!/usr/bin/env bash
# 直前の promote.sh が rollback-candidate タグを付けたイメージ(=入れ替え前の本番)を
# 本番へ再デプロイする。再ビルドはしない。
#
# 安全確認: rust-op-staging の現在の中身が、記録した rollback-candidate と一致しない場合は
# 拒否する。次のリリース検証で既に staging が上書きされている場合、誤ってその「検証中の
# 新バージョン」を本番へロールバックとして流し込んでしまう事故を防ぐため。
#
# 使い方:
#   scripts/rollback.sh                              # ドライラン
#   scripts/rollback.sh --apply                       # 実行
#   scripts/rollback.sh --apply --force-image <参照>  # 安全確認を無視して特定イメージへ戻す

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib_cloud_run.sh"

PROJECT="${PROJECT:-fido2-8b943}"
REGION="${REGION:-asia-northeast1}"
PROD_SERVICE="${PROD_SERVICE:-rust-op}"
STAGING_SERVICE="${STAGING_SERVICE:-rust-op-staging}"

APPLY=0
FORCE_IMAGE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --force-image) FORCE_IMAGE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$FORCE_IMAGE" ]]; then
  target_image="$FORCE_IMAGE"
  [[ "$target_image" == *"@sha256:"* ]] \
    || { echo "ERROR: --force-image は digest 付き参照である必要があります: '${target_image}'" >&2; exit 1; }
  echo "WARNING: --force-image 指定、安全確認をスキップします: ${target_image}"
else
  candidate=""
  for pkg in "${KNOWN_PACKAGES[@]}"; do
    p="$(image_path_for "$pkg")"
    d="$(resolve_ar_tag "$p" "rollback-candidate" || true)"
    if [[ -n "$d" ]]; then
      candidate="${p}@${d}"
      break
    fi
  done
  if [[ -z "$candidate" ]]; then
    echo "ERROR: rollback-candidate タグが見つかりません（promote.sh が一度も成功していません）。" >&2
    echo "       意図的に特定イメージへ戻す場合は --force-image <digest参照> を使ってください。" >&2
    exit 1
  fi
  current_staging_image="$(traffic100_image "$STAGING_SERVICE")"
  if [[ "$current_staging_image" != "$candidate" ]]; then
    echo "ERROR: rust-op-staging の現在のイメージが記録済み rollback-candidate と一致しません。" >&2
    echo "       既に次のリリース検証で staging が上書きされている可能性があり、安全なロールバックではありません。" >&2
    echo "       記録済み  : ${candidate}" >&2
    echo "       staging現在: ${current_staging_image}" >&2
    echo "       意図的に上書きする場合は --force-image <digest参照> を使ってください。" >&2
    exit 1
  fi
  target_image="$candidate"
fi

echo "rollback target: ${target_image}"
if (( APPLY == 0 )); then
  echo "[dry-run]"
  exit 0
fi

deploy_image_verified "$PROD_SERVICE" "$target_image"
set_global_tag "$target_image" "prod-live"
echo "rollback complete."
