#!/usr/bin/env bash
# deploy_staging.sh / promote.sh / rollback.sh / cleanup_cloud_run.sh から source される
# 共通ヘルパー。単体実行はしない。
#
# `gcloud run services describe --format="value(status.traffic...)"` は繰り返しフィールドに
# 対して Python の dict repr をセミコロン区切りで返すだけで安全にパースできない
# （`jq` 不可）。かつ `spec.template.spec.containers[0].image` は「最新作成されたリビジョン」の
# 値であり「100%トラフィックのリビジョン」とは限らない（0%トラフィックのタグ付きリビジョンが
# 残っている場合がある）。そのため「今まさに100%トラフィックを受けている image」は必ず
# `--format=json` + `jq` で status.traffic を見て revisionName を特定し、そのリビジョンを
# 個別に describe する、という2段階の経路を通す。

traffic100_revision() {  # $1=service -> revisionName（percent==100 が1件でなければエラー）
  local service="$1" json count
  json="$(gcloud run services describe "$service" --region="$REGION" --project="$PROJECT" --format=json)"
  count="$(jq '[.status.traffic[]? | select(.percent == 100)] | length' <<<"$json")"
  if [[ "$count" != "1" ]]; then
    echo "ERROR: ${service}: percent=100 のトラフィックが ${count} 件（1件である必要あり）" >&2
    jq '.status.traffic' <<<"$json" >&2
    return 1
  fi
  jq -r '[.status.traffic[] | select(.percent == 100)][0].revisionName' <<<"$json"
}

traffic100_image() {  # $1=service -> digest付き完全修飾イメージ参照
  local service="$1" revision image
  revision="$(traffic100_revision "$service")" || return 1
  image="$(gcloud run revisions describe "$revision" --region="$REGION" --project="$PROJECT" \
            --format="value(spec.containers[0].image)")"
  [[ "$image" == *"@sha256:"* ]] || { echo "ERROR: not digest-pinned: ${image}" >&2; return 1; }
  echo "$image"
}

KNOWN_PACKAGES=(rust-op rust-op-staging)  # promote.sh/rollback.sh がイメージを行き来させる対象パッケージ

image_path_for() {  # $1=パッケージ名(サービス名と一致) -> Artifact Registry イメージパス
  # gcloud run deploy --source . はデプロイ先サービス名でイメージ名を自動採番するため、
  # サービスごとに別の Artifact Registry パス(パッケージ)になる。
  echo "asia-northeast1-docker.pkg.dev/${PROJECT}/cloud-run-source-deploy/$1"
}

array_contains() {  # $1=探す値、残りの引数=配列要素
  local needle="$1"; shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

move_ar_tag() {  # $1=digest参照 $2=タグ名: 作成 or 付け替え
  local digest_ref="$1" tag="$2"
  gcloud artifacts docker tags add "$digest_ref" "${digest_ref%@*}:${tag}" --quiet
}

resolve_ar_tag() {  # $1=イメージパス(パッケージ) $2=タグ名 -> digest文字列 or 空
  gcloud artifacts tags list --package="$(basename "$1")" \
    --repository=cloud-run-source-deploy --location="$REGION" --project="$PROJECT" \
    --format="value(version)" --filter="name:${2}" 2>/dev/null | head -n1
}

set_global_tag() {  # $1=digest参照 $2=タグ名: 全パッケージから同名タグを外してから対象へ付け直す
  # AR の Docker タグはパッケージ(イメージパス)ごとに独立した名前空間を持つ。promote.sh は
  # prod<->staging でイメージを行き来させるたびに、そのイメージが元々属するパッケージが
  # rust-op と rust-op-staging の間で入れ替わる。単純に move_ar_tag するだけだと前回タグを
  # 付けた側のパッケージに古いタグが残り続け、rollback.sh がどちらのパッケージを先に見るかで
  # 「本当に最新のrollback-candidate」ではなく古いタグを拾ってしまう事故が起きる
  # (prod-live/rollback-candidate のように「常に高々1つだけ存在すべき」タグはこちらを使う)。
  local digest_ref="$1" tag="$2" pkg p existing
  for pkg in "${KNOWN_PACKAGES[@]}"; do
    p="$(image_path_for "$pkg")"
    existing="$(resolve_ar_tag "$p" "$tag" || true)"
    if [[ -n "$existing" ]]; then
      gcloud artifacts docker tags delete "${p}:${tag}" --quiet 2>/dev/null || true
    fi
  done
  move_ar_tag "$digest_ref" "$tag"
}

smoke_test_url() {  # $1=base_url: 既知のエンドポイントを確認し、いずれか失敗すれば非0を返す
  local base_url="$1" path code failed=0
  for path in "/oidc/.well-known/openid-configuration" "/oidc/jwks"; do
    code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${base_url}${path}" || echo "000")"
    if [[ "$code" != "200" ]]; then
      echo "  smoke test failed: ${base_url}${path} -> ${code}" >&2
      failed=1
    else
      echo "  ok: ${base_url}${path} -> ${code}"
    fi
  done
  return "$failed"
}

new_revision_suffix() {  # 一意なリビジョンsuffixを生成（Cloud Run制約: ^[a-z]([-a-z0-9]*[a-z0-9])?$）
  echo "d$(date +%Y%m%d%H%M%S)$(printf '%04x' "$RANDOM")"
}

switch_traffic() {  # $1=service $2=revision名: 明示したリビジョン名へ100%を割り当てる
  local service="$1" revision="$2"
  gcloud run services update-traffic "$service" --region="$REGION" --project="$PROJECT" \
    --to-revisions="${revision}=100" --quiet
}

# 実運用で、status.latestReadyRevisionName を経由する経路（force_full_traffic/
# deploy_image_verified の旧実装）が繰り返し不整合を起こすことを確認した:
# 新規リビジョンがReadyになった直後にActive=false/Retiredへ遷移し、CLI出力・
# status.latestReadyRevisionNameのどちらも古い（無関係な）リビジョン名を報告し続けた。
# 唯一確実に動作したのは「こちらが --revision-suffix で明示的に決めた名前」をそのまま
# describe/update-traffic に使う経路（サーバ側の「最新」判定への問い合わせを一切挟まない）
# だったため、以下の関数群はすべてこのパターンに統一する。
#
# さらに、旧 deploy_image_verified は --no-traffic を付けずにデプロイしていたため、
# サービスの過去のトラフィック来歴によっては gcloud run deploy 自体がイメージ検証より
# 前にトラフィックを切り替えてしまい、検証に失敗しても手遅れという事故が実際に起きた。
# 検証と切替を確実に分離するため、常に --no-traffic でリビジョンを作成し、検証が
# 通った場合にのみ switch_traffic を呼ぶ。

deploy_image_verified() {  # $1=service $2=デプロイしたいimage参照(digest付き)
  local service="$1" expected_image="$2" suffix revision actual_image
  suffix="$(new_revision_suffix)"
  revision="${service}-${suffix}"
  gcloud run deploy "$service" --image "$expected_image" --revision-suffix "$suffix" \
    --no-traffic --region="$REGION" --project="$PROJECT" --quiet
  actual_image="$(gcloud run revisions describe "$revision" --region="$REGION" --project="$PROJECT" \
    --format="value(spec.containers[0].image)")"
  if [[ "$actual_image" != "$expected_image" ]]; then
    echo "ERROR: gcloud run deploy が指定と異なるイメージを使いました（既知の再現性ある異常動作）。" >&2
    echo "       service : ${service}" >&2
    echo "       期待    : ${expected_image}" >&2
    echo "       実際    : ${actual_image} (revision: ${revision})" >&2
    echo "       トラフィックは切り替えていません。手動で確認・修正してください。" >&2
    return 1
  fi
  switch_traffic "$service" "$revision"
}

deploy_source_verified() {  # $1=service: ソースからビルドし、トラフィックは切り替えずに
                             # 作成されたリビジョン名を標準出力へ返す（呼び出し側が switch_traffic する）
  # commit-sha ラベルは Cloud Run コンソール上でリビジョンとgitコミットを突き合わせるための
  # ものなので、ここ(実際にソースからビルドする経路)にのみ付与する。deploy_image_verified は
  # 既にビルド済みのイメージを別サービスへ動かすだけで「今のgit HEAD」とは無関係なため付けない。
  local service="$1" suffix revision commit_sha
  suffix="$(new_revision_suffix)"
  revision="${service}-${suffix}"
  commit_sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  gcloud run deploy "$service" --source . --revision-suffix "$suffix" \
    --no-traffic --region="$REGION" --project="$PROJECT" \
    --update-labels="commit-sha=${commit_sha}" --quiet
  echo "$revision"
}
