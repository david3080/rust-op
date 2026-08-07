#!/usr/bin/env bash
# 本番(rust-op)とstaging(rust-op-staging)の間でコンテナイメージを入れ替える。
# 再ビルドはしない: staging で検証済みのイメージをそのまま本番へ、本番の(入れ替え前の)
# イメージをそのまま staging へ、それぞれ --image 指定でデプロイするだけ。
#
# 昇格直後、staging には「ついさっきまで本番だった旧バージョン」が残るため、比較・
# ロールバック・不具合切り分け（今回の不具合が前回リリースにも既にあったか）に使える。
#
# --staging-image は GitHub Actions から「deploy-staging ジョブが実際に検証したdigest」を
# 明示的に渡すためのもの（省略時は staging の現在値を都度取得する簡易パス。ローカル手動
# 実行向け。GitHub Actions 側では省略しない — 承認待ちの間に別の push が staging を
# 上書きしていた場合に、レビュアーが確認したものと違うビルドを昇格してしまう事故を防ぐため）。
# 空文字が渡された場合も「省略」と誤認しないよう、フラグが渡されたかどうか自体を別に追跡する。
#
# 本番への切替は複数のAPI呼び出しにまたがり真のアトミック性はない。そのため
# 「本番の安全性を最優先」の順序で進める: 本番だけを先に切り替えてスモークテストし、
# 失敗すれば直前のリビジョンへ即座に戻す。ここを通過して初めて staging 入れ替え・
# タグ更新に進む（万一そこで失敗しても、本番は既に確認済みの状態で止まる）。
#
# 使い方:
#   scripts/promote.sh                                    # ドライラン
#   scripts/promote.sh --apply                             # 実行(stagingの現在値を使う)
#   scripts/promote.sh --apply --staging-image <digest参照> # 実行(digestを明示)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib_cloud_run.sh"

PROJECT="${PROJECT:-fido2-8b943}"
REGION="${REGION:-asia-northeast1}"
PROD_SERVICE="${PROD_SERVICE:-rust-op}"
STAGING_SERVICE="${STAGING_SERVICE:-rust-op-staging}"
PROD_URL="${PROD_URL:-https://oidc.sonrisa.co.jp}"
STAGING_URL="${STAGING_URL:-https://test.sonrisa.co.jp}"

APPLY=0
STAGING_IMAGE_OVERRIDE=""
STAGING_IMAGE_PASSED=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --staging-image) STAGING_IMAGE_OVERRIDE="$2"; STAGING_IMAGE_PASSED=1; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

prev_prod_revision="$(traffic100_revision "$PROD_SERVICE")"
prev_prod_image="$(gcloud run revisions describe "$prev_prod_revision" --region="$REGION" --project="$PROJECT" \
  --format="value(spec.containers[0].image)")"

if (( STAGING_IMAGE_PASSED )); then
  new_image="$STAGING_IMAGE_OVERRIDE"
  [[ -n "$new_image" && "$new_image" == *"@sha256:"* ]] \
    || { echo "ERROR: --staging-image に空または digest 未指定の値が渡されました: '${new_image}'" >&2; exit 1; }
else
  new_image="$(traffic100_image "$STAGING_SERVICE")"
fi

echo "prev_prod_image = ${prev_prod_image}"
echo "new_image       = ${new_image}"
if [[ "$prev_prod_image" == "$new_image" ]]; then
  echo "ERROR: 本番の現在イメージと staging のイメージが同一です。promote の再実行、または" >&2
  echo "       staging が更新されないまま呼ばれた可能性があります。このまま進めると" >&2
  echo "       rollback-candidate タグが現在稼働中と同じdigestに潰れ、実質的なロールバック" >&2
  echo "       手段を失います。意図的な操作であれば、確認のうえ手動で対応してください。" >&2
  exit 1
fi

if (( APPLY == 0 )); then
  echo "[dry-run]"
  exit 0
fi

deploy_image_verified "$PROD_SERVICE" "$new_image"
echo "smoke testing ${PROD_URL} ..."
if ! smoke_test_url "$PROD_URL"; then
  echo "ERROR: 本番のスモークテストに失敗しました。${prev_prod_revision} へトラフィックを戻します。" >&2
  switch_traffic "$PROD_SERVICE" "$prev_prod_revision"
  exit 1
fi

deploy_image_verified "$STAGING_SERVICE" "$prev_prod_image"
echo "smoke testing ${STAGING_URL} ..."
if ! smoke_test_url "$STAGING_URL"; then
  echo "WARNING: staging(入れ替え後)のスモークテストに失敗しました。本番は既に切替・確認済みです。" >&2
  echo "         staging 側は手動で確認してください。" >&2
fi

set_global_tag "$new_image" "prod-live"
set_global_tag "$prev_prod_image" "rollback-candidate"
echo "promote complete."
