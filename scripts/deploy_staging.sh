#!/usr/bin/env bash
# rust-op-staging (test.sonrisa.co.jp) へソースからビルド・デプロイし、100%トラフィックで
# 即座に公開する。staging は本番の0%トラフィックタグ付きcandidateとは違い専用プレビュー
# サービスなので、タグ/トラフィック分割は不要。
#
# WebAuthn/passkey は RP ID(ドメイン) に認証情報が紐づくため、本番と同じ固定ドメインで
# 検証できることが staging を使う最大の理由。Cloud Run の一時URLでは別のRP IDになり
# 本番用に登録した passkey では検証できない。
#
# スモークテストに失敗した場合は直前のリビジョンへトラフィックを自動で戻す。
#
# 使い方:
#   scripts/deploy_staging.sh              # ドライラン
#   scripts/deploy_staging.sh --apply       # 実際にデプロイ

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib_cloud_run.sh"

PROJECT="${PROJECT:-fido2-8b943}"
REGION="${REGION:-asia-northeast1}"
STAGING_SERVICE="${STAGING_SERVICE:-rust-op-staging}"
SMOKE_URL="${SMOKE_URL:-$(service_base_url "$STAGING_SERVICE")}"

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
if (( APPLY == 0 )); then
  echo "[dry-run] gcloud run deploy ${STAGING_SERVICE} --source . (region=${REGION})"
  exit 0
fi

prev_revision="$(traffic100_revision "$STAGING_SERVICE" 2>/dev/null || echo "")"

new_revision="$(deploy_source_verified "$STAGING_SERVICE")"
if ! verify_pending "$STAGING_SERVICE"; then
  echo "ERROR: 切替前の確認に失敗しました（revision: ${new_revision}）。" >&2
  echo "       **トラフィックは切り替えていません。staging は前のリビジョンのままです。**" >&2
  exit 1
fi
switch_traffic "$STAGING_SERVICE" "$new_revision"
staging_image="$(gcloud run revisions describe "$new_revision" --region="$REGION" --project="$PROJECT" \
  --format="value(spec.containers[0].image)")"

echo "smoke testing ${SMOKE_URL} ..."
if ! smoke_test_url "$SMOKE_URL"; then
  if [[ -n "$prev_revision" ]]; then
    echo "reverting ${STAGING_SERVICE} traffic to ${prev_revision}"
    switch_traffic "$STAGING_SERVICE" "$prev_revision"
  fi
  exit 1
fi

echo "staging deployed and smoke-tested: ${SMOKE_URL}"
echo "STAGING_IMAGE=${staging_image}"
