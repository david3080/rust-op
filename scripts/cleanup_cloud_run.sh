#!/usr/bin/env bash
# Cloud Run (rust-op / rust-op-staging) の古いコンテナイメージ・リビジョンを削除する。
# Artifact Registry のクリーンアップポリシーは実行タイミングが不透明なため、
# デプロイ側で確実に保持数を制御する（ops/cleanup-cloud-run-artifacts）。
#
# blue/green の入れ替え(promote.sh/rollback.sh)により、あるサービスの image path 由来
# ではない digest が別サービスで現在稼働中、ということが意図的に起こる（例: rust-op
# パス由来のイメージが rust-op-staging で稼働中）。そのため「今どこかのサービスで
# 100%トラフィックを受けている digest」はパスに関係なく無条件で保護し、
# 保持件数(KEEP_IMAGES)の枠を消費させない。
#
# 既定はドライラン（削除対象の一覧表示のみ）。実際に削除するには --apply を渡す。
#
# 使い方:
#   scripts/cleanup_cloud_run.sh              # ドライラン
#   scripts/cleanup_cloud_run.sh --apply       # 実際に削除

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib_cloud_run.sh"

PROJECT="${PROJECT:-fido2-8b943}"
REGION="${REGION:-asia-northeast1}"
KEEP_IMAGES="${KEEP_IMAGES:-10}"
KEEP_REVISIONS="${KEEP_REVISIONS:-5}"
SERVICES=(rust-op rust-op-staging)

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
fi

echo "=== 稼働中イメージの保護対象を収集 ==="
protected_digests=()
for s in "${SERVICES[@]}"; do
  img="$(traffic100_image "$s" 2>/dev/null || echo "")"
  if [[ -n "$img" ]]; then
    d="${img#*@}"
    protected_digests+=("$d")
    echo "  ${s}: ${d} を保護"
  else
    echo "  ${s}: 100%トラフィックのリビジョンを特定できず（スキップ）"
  fi
done
# rollback-candidate は「今どこかで稼働中」ではないが rollback.sh の復元先そのものなので、
# 現在トラフィックが向いていなくても削除されては困る。prod-live は稼働中digestと通常一致
# するが、念のため同様に保護対象へ加える。
for tag in prod-live rollback-candidate; do
  for pkg in "${KNOWN_PACKAGES[@]}"; do
    p="$(image_path_for "$pkg")"
    d="$(resolve_ar_tag "$p" "$tag" || true)"
    if [[ -n "$d" ]]; then
      protected_digests+=("$d")
      echo "  タグ ${tag} (${pkg}): ${d} を保護"
    fi
  done
done

is_protected() { array_contains "$1" "${protected_digests[@]:-}"; }

for s in "${SERVICES[@]}"; do
  IMAGE="$(image_path_for "$s")"
  echo ""
  echo "=== Artifact Registry イメージ (${IMAGE}) ==="
  echo "稼働中のものに加え、直近 ${KEEP_IMAGES} 件を保持、それ以外を削除対象とする。"

  all_images=()
  while IFS=$'\t' read -r digest created; do
    [[ -z "$digest" ]] && continue
    all_images+=("${digest}"$'\t'"${created}")
  done < <(
    gcloud artifacts docker images list "$IMAGE" \
      --format="value(version,createTime)" \
      --sort-by="~createTime" 2>/dev/null
  )

  kept_unprotected=0
  image_delete_count=0
  for entry in "${all_images[@]:-}"; do
    [[ -z "$entry" ]] && continue
    digest="$(echo "$entry" | cut -f1)"
    created="$(echo "$entry" | cut -f2)"
    if is_protected "$digest"; then
      echo "  保持(稼働中): ${digest}"
      continue
    fi
    if (( kept_unprotected < KEEP_IMAGES )); then
      kept_unprotected=$((kept_unprotected + 1))
      continue
    fi
    echo "  削除対象: ${digest} (作成: ${created})"
    image_delete_count=$((image_delete_count + 1))
    if (( APPLY == 1 )); then
      gcloud artifacts docker images delete "${IMAGE}@${digest}" --quiet --delete-tags
    fi
  done
  echo "イメージ削除対象(${s}): ${image_delete_count} 件"
done

echo ""

is_traffic_revision() { array_contains "$1" "${traffic_revisions[@]:-}"; }

for s in "${SERVICES[@]}"; do
  SERVICE="$s"
  echo "=== Cloud Run リビジョン (${SERVICE}) ==="
  echo "直近 ${KEEP_REVISIONS} 件 + トラフィックを受けているリビジョンを保持、それ以外を削除対象とする。"

  traffic_revisions=()
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    traffic_revisions+=("$name")
  done < <(
    gcloud run services describe "$SERVICE" --region="$REGION" --project="$PROJECT" \
      --format="value(status.traffic.revisionName)" 2>/dev/null | tr ';' '\n'
  )

  all_revisions=()
  while IFS=$'\t' read -r name created; do
    [[ -z "$name" ]] && continue
    all_revisions+=("${name}"$'\t'"${created}")
  done < <(
    gcloud run revisions list --service="$SERVICE" --region="$REGION" --project="$PROJECT" \
      --format="value(metadata.name,metadata.creationTimestamp)" \
      --sort-by="~metadata.creationTimestamp" 2>/dev/null
  )

  revision_delete_count=0
  for i in "${!all_revisions[@]}"; do
    name="$(echo "${all_revisions[$i]}" | cut -f1)"
    created="$(echo "${all_revisions[$i]}" | cut -f2)"
    if (( i < KEEP_REVISIONS )); then
      continue
    fi
    if is_traffic_revision "$name"; then
      echo "  保持(トラフィック中): ${name}"
      continue
    fi
    echo "  削除対象: ${name} (作成: ${created})"
    revision_delete_count=$((revision_delete_count + 1))
    if (( APPLY == 1 )); then
      gcloud run revisions delete "$name" --region="$REGION" --project="$PROJECT" --quiet
    fi
  done
  echo "リビジョン削除対象(${SERVICE}): ${revision_delete_count} 件"
  echo ""
done

if (( APPLY == 0 )); then
  echo "ドライランのみ。実際に削除するには --apply を付けて再実行してください。"
fi
