#!/usr/bin/env bash
# Cloud Run (rust-op) の古いコンテナイメージ・リビジョンを削除する。
# Artifact Registry のクリーンアップポリシーは実行タイミングが不透明なため、
# デプロイ側で確実に保持数を制御する（ops/cleanup-cloud-run-artifacts）。
#
# 既定はドライラン（削除対象の一覧表示のみ）。実際に削除するには --apply を渡す。
#
# 使い方:
#   scripts/cleanup_cloud_run.sh              # ドライラン
#   scripts/cleanup_cloud_run.sh --apply       # 実際に削除

set -euo pipefail

PROJECT="${PROJECT:-fido2-8b943}"
REGION="${REGION:-asia-northeast1}"
SERVICE="${SERVICE:-rust-op}"
IMAGE="${IMAGE:-asia-northeast1-docker.pkg.dev/fido2-8b943/cloud-run-source-deploy/rust-op}"
KEEP_IMAGES="${KEEP_IMAGES:-10}"
KEEP_REVISIONS="${KEEP_REVISIONS:-5}"

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
fi

echo "=== Artifact Registry イメージ (${IMAGE}) ==="
echo "直近 ${KEEP_IMAGES} 件を保持、それ以外を削除対象とする。"

all_images=()
while IFS=$'\t' read -r digest created; do
  [[ -z "$digest" ]] && continue
  all_images+=("${digest}"$'\t'"${created}")
done < <(
  gcloud artifacts docker images list "$IMAGE" \
    --format="value(version,createTime)" \
    --sort-by="~createTime" 2>/dev/null
)

image_delete_count=0
for i in "${!all_images[@]}"; do
  if (( i < KEEP_IMAGES )); then
    continue
  fi
  digest="$(echo "${all_images[$i]}" | cut -f1)"
  created="$(echo "${all_images[$i]}" | cut -f2)"
  echo "  削除対象: ${digest} (作成: ${created})"
  image_delete_count=$((image_delete_count + 1))
  if (( APPLY == 1 )); then
    gcloud artifacts docker images delete "${IMAGE}@${digest}" --quiet --delete-tags
  fi
done
echo "イメージ削除対象: ${image_delete_count} 件"
echo ""

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

is_traffic_revision() {
  local name="$1"
  for tr in "${traffic_revisions[@]:-}"; do
    if [[ "$tr" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}

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
echo "リビジョン削除対象: ${revision_delete_count} 件"

if (( APPLY == 0 )); then
  echo ""
  echo "ドライランのみ。実際に削除するには --apply を付けて再実行してください。"
fi
