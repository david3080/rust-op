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

# サービスと公開URLの対応はここが唯一の持ち場。rollback.sh のようにURLを持たない
# 呼び出し元からも service_base_url() で引けるようにしてある。
PROD_SERVICE="${PROD_SERVICE:-rust-op}"
STAGING_SERVICE="${STAGING_SERVICE:-rust-op-staging}"
PROD_URL="${PROD_URL:-https://oidc.sonrisa.co.jp}"
STAGING_URL="${STAGING_URL:-https://test.sonrisa.co.jp}"
BASE_PATH="${BASE_PATH:-/oidc}"
# トラフィックを受ける前のリビジョンに付けるタグ。Cloud Run はタグごとに
# `https://<tag>---<service>-<hash>.<region>.run.app` という個別URLを発行するので、
# 0%のまま実際にHTTPを投げて確かめられる。昇格後もタグは残す(稼働中リビジョンを
# 名指しで叩けるほうが調査に効くため)。
PENDING_TAG="${PENDING_TAG:-pending}"

service_base_url() {  # $1=service -> そのサービスの公開URL
  case "$1" in
    "$PROD_SERVICE") echo "$PROD_URL" ;;
    "$STAGING_SERVICE") echo "$STAGING_URL" ;;
    *) echo "ERROR: 公開URLが未登録のサービスです: $1" >&2; return 1 ;;
  esac
}

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

tag_url() {  # $1=service $2=tag -> そのタグが指すリビジョンのURL(無ければ空)
  gcloud run services describe "$1" --region="$REGION" --project="$PROJECT" --format=json \
    | jq -r --arg t "$2" '[.status.traffic[]? | select(.tag == $t)][0].url // empty'
}

# トラフィックを1%も受けていないリビジョンに対して、実際にHTTPを投げて機能を確かめる。
# smoke_test_url が公開URL(=切替後)を叩くのに対し、こちらはタグURL(=切替前)を叩く。
#
# ここで選んだ4つは、それぞれ別の依存を通る:
#   discovery              経路と設定(issuer が ORIGIN から組まれている)
#   jwks                   KMS の署名鍵が引けている
#   end-session(登録済みURI) Firestore の登録を引いて戻り先を許している(303)
#   end-session(未登録URI)   同じ口が、登録に無い戻り先を拒んでいる(400)
# 後ろ2つは対で意味を持つ。303 が 400 に化けると 2026-09-16 のサインアウト不能が再発し、
# 400 が 303 に化けると誰の戻り先でも通る(オープンリダイレクト)。片方だけでは
# どちらの壊れ方も見逃す。demo-rp は本番・staging の両方に在る静的な登録なので、
# 環境ごとの設定を持ち込まずに済む(2026-09-20 に両環境で 303/400 を実測)。
#
# タグURLはホスト名が公開URLと異なるため、WebAuthn のように origin を検証する経路は
# ここでは確かめられない(FIDO_ORIGIN は公開URLで焼かれている)。それらは切替後の
# smoke_test_url と人手の確認に残る。
pending_checks() {  # $1=プローブ先URL $2=期待するissuer
  local probe="$1" want_issuer="$2" failed=0 code issuer keys
  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${probe}${BASE_PATH}/.well-known/openid-configuration" || echo 000)"
  issuer="$(curl -s --max-time 10 "${probe}${BASE_PATH}/.well-known/openid-configuration" | jq -r '.issuer // empty' 2>/dev/null || true)"
  if [[ "$code" != "200" || "$issuer" != "$want_issuer" ]]; then
    echo "  pending check failed: discovery -> ${code} issuer='${issuer}' (期待: 200 '${want_issuer}')" >&2
    failed=1
  else
    echo "  ok: discovery -> 200 issuer=${issuer}"
  fi

  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${probe}${BASE_PATH}/jwks" || echo 000)"
  keys="$(curl -s --max-time 10 "${probe}${BASE_PATH}/jwks" | jq -r '.keys | length' 2>/dev/null || echo 0)"
  if [[ "$code" != "200" || ! "$keys" =~ ^[0-9]+$ || "$keys" -lt 1 ]]; then
    echo "  pending check failed: jwks -> ${code} keys=${keys} (期待: 200 かつ1本以上)" >&2
    failed=1
  else
    echo "  ok: jwks -> 200 keys=${keys}"
  fi

  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    "${probe}${BASE_PATH}/end-session?client_id=demo-rp&post_logout_redirect_uri=${want_issuer}/" || echo 000)"
  if [[ "$code" != "303" ]]; then
    echo "  pending check failed: end-session(登録済みURI) -> ${code} (期待: 303)" >&2
    failed=1
  else
    echo "  ok: end-session(登録済みURI) -> 303"
  fi

  code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    "${probe}${BASE_PATH}/end-session?client_id=demo-rp&post_logout_redirect_uri=https://not-registered.example.com/" || echo 000)"
  if [[ "$code" != "400" ]]; then
    echo "  pending check failed: end-session(未登録URI) -> ${code} (期待: 400)" >&2
    failed=1
  else
    echo "  ok: end-session(未登録URI) -> 400"
  fi

  return "$failed"
}

verify_pending() {  # $1=service: PENDING_TAG が指すリビジョンを、切替前に確かめる
  local service="$1" probe want_issuer
  probe="$(tag_url "$service" "$PENDING_TAG")"
  if [[ -z "$probe" ]]; then
    echo "ERROR: ${service}: タグ ${PENDING_TAG} のURLが取得できません。切替前の確認ができないため中止します。" >&2
    return 1
  fi
  want_issuer="$(service_base_url "$service")${BASE_PATH}" || return 1
  echo "pending checks on ${probe} (0% traffic) ..."
  pending_checks "$probe" "$want_issuer"
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
#
# その「検証」は当初イメージのdigest照合だけで、機能が動くかは切替後の smoke_test_url まで
# 分からなかった。つまり壊れた版は一度は利用者に出てから巻き戻る。本番のトラフィックは
# 1日36件(404の探査を除いた実数、2026-09-20実測)しかなく、割合を絞って様子を見る形は
# 標本が集まらないので成立しない。そこで「こちらから合成の要求を投げて標本を作る」形にし、
# --tag で発行される0%のURLに対して verify_pending を通してから切り替える。

deploy_image_verified() {  # $1=service $2=デプロイしたいimage参照(digest付き)
  local service="$1" expected_image="$2" suffix revision actual_image
  suffix="$(new_revision_suffix)"
  revision="${service}-${suffix}"
  gcloud run deploy "$service" --image "$expected_image" --revision-suffix "$suffix" \
    --no-traffic --tag "$PENDING_TAG" --region="$REGION" --project="$PROJECT" --quiet
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
  if ! verify_pending "$service"; then
    echo "ERROR: ${service}: 切替前の確認に失敗しました（revision: ${revision}）。" >&2
    echo "       **トラフィックは1%も切り替えていません。稼働中のリビジョンはそのままです。**" >&2
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
    --no-traffic --tag "$PENDING_TAG" --region="$REGION" --project="$PROJECT" \
    --update-labels="commit-sha=${commit_sha}" --quiet
  echo "$revision"
}
