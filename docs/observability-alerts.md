# 検知の土台: アラート可能イベントと閾値（ZT Behavioral monitoring / Foundation）

[Zero Trust 自己評価](./zero-trust-assessment.md) の領域4（Behavioral monitoring）**Foundation tier** の実体。
枠組みの Foundation は「**期待される挙動を手で定義**し、**逸脱に閾値ベースのアラート**を張る」こと。

rust-op は Cloud Run + Cloud Logging 上で動くため、責務は2つに分かれる:
- **アプリ（コード, 実装済）**: アラート可能なセキュリティイベントを構造化ログで一貫して emit する。
- **監視（Cloud Monitoring, config）**: そのイベントに log-based metric ＋閾値アラートポリシーを張る。

**アプリ側の信号は既に揃っている**（下表）。本書はその信号の意味・期待ベースライン・閾値ポリシーを定義する。
アプリ内アラートは作らない（Cloud Monitoring 側で閾値を持つのが Foundation の形）。

> Enterprise/Advanced（自動 first-pass triage・統計的異常検知・SOAR）は対象外。本書は Foundation（信号＋閾値）まで。

## アラート可能イベント（アプリが emit 済み）

tracing-json 構造: イベント名は `jsonPayload.fields.event`、付随フィールドも `jsonPayload.fields.*`、
span 由来（request_id）は `jsonPayload.span.request_id`。severity は tracing level に対応（WARN→`WARNING` / ERROR→`ERROR`）。

| event | severity | 何の信号 | 期待ベースライン | 推奨閾値（Foundation） |
|---|---|---|---|---|
| `client_auth_failed` | WARN | token endpoint のクライアント認証失敗＝**資格情報攻撃/鍵不整合** | ほぼ 0（confidential client は正しい鍵を持つ） | 例: 5分窓で > 10 |
| `login_failed` | WARN | passkey 認証失敗＝**ブルートフォース/不正試行** | login_success に対し小比率 | 例: 5分窓で > 20、または failed/success 比 > 0.5 |
| `kms_sign_failed` | ERROR | 署名鍵の署名失敗＝**完全性/可用性の毀損**（A2） | **0** | **1 件でも即アラート** |
| `http_request` (status≥500) | INFO | サーバ内部エラー率＝**可用性** | ほぼ 0 | 例: 5分窓で 5xx 率 > 1% または > 5 件 |
| `dcr_client_registered` | INFO | 動的クライアント登録＝**登録の濫用**（IAT 漏洩時） | 稀（IAT ゲート/手動） | 例: 1時間窓で > 3 |
| `token_issued` | INFO | トークン発行量＝**異常な発行スパイク** | 平常のベースライン量 | 例: 平常比 × 5 の急増（高水位閾値） |

補助シグナル: `http_request` の `latency_ms`（dwell/性能）、`login_success`/`token_issued` の量（正常ベースライン）。
**注意**: `token_issued`/`login_success` は `fields.sub`（メール=PII）を含む。集計/アラートには使うが、PII の取り扱いは
[Zero Trust 自己評価](./zero-trust-assessment.md) の output-control 観察（将来 pseudonymize 候補）を参照。

## 期待ベースライン（「正常」の手定義 = Foundation）

- `kms_sign_failed`・5xx は **0 が正常**。1 件でも調査対象。
- `client_auth_failed` は **ほぼ 0**（confidential client は private_key_jwt の正しい鍵を持つ）。継続的な発生＝鍵不整合か攻撃。
- `login_failed` は `login_success` に対し**小比率**。比率の上昇＝資格情報攻撃の兆候。
- `dcr_client_registered` は**稀**（IAT ゲート）。連続発生＝IAT 漏洩の疑い。
- `token_issued` は**平常量**。桁違いの急増＝異常。

## Cloud Monitoring への張り方（実行 snippet・適用はゲート）

通知先（メール/Slack 等）の選択は運用判断なので、**ポリシー作成は明示指示で行う**（デプロイと同様にゲート）。
以下は project `fido2-8b943`・service `api` 前提。

### 1) log-based counter metric（イベントを数える）

```sh
# 例: client_auth_failed を数える counter metric
gcloud logging metrics create rust_op_client_auth_failed \
  --project=fido2-8b943 \
  --description="token endpoint client auth failures (credential attack signal)" \
  --log-filter='resource.type="cloud_run_revision" resource.labels.service_name="api" jsonPayload.fields.event="client_auth_failed"'

# kms_sign_failed（0 が正常・1 件で警報）
gcloud logging metrics create rust_op_kms_sign_failed \
  --project=fido2-8b943 \
  --description="KMS signing failures (integrity/availability)" \
  --log-filter='resource.type="cloud_run_revision" resource.labels.service_name="api" jsonPayload.fields.event="kms_sign_failed"'

# 5xx（http_request の status>=500）
gcloud logging metrics create rust_op_http_5xx \
  --project=fido2-8b943 \
  --description="server-side 5xx rate" \
  --log-filter='resource.type="cloud_run_revision" resource.labels.service_name="api" jsonPayload.fields.event="http_request" jsonPayload.fields.status>=500'
```

`login_failed` / `dcr_client_registered` も同様に `jsonPayload.fields.event="..."` で作成。

### 2) 閾値アラートポリシー（通知先 = 要ユーザ選択）

`kms_sign_failed` は 1 件で即アラート、ほかは窓内レート閾値。代表例（`--notification-channels` は運用で用意した channel ID を入れる）:

```sh
# kms_sign_failed: 1 件でも発火
gcloud alpha monitoring policies create \
  --project=fido2-8b943 \
  --display-name="rust-op: KMS sign failed" \
  --condition-display-name="kms_sign_failed >= 1 (5m)" \
  --condition-filter='metric.type="logging.googleapis.com/user/rust_op_kms_sign_failed" resource.type="cloud_run_revision"' \
  --condition-threshold-value=0 \
  --condition-threshold-comparison=COMPARISON_GT \
  --condition-threshold-duration=0s \
  --aggregation='{"alignmentPeriod":"300s","perSeriesAligner":"ALIGN_SUM"}'
  # --notification-channels=projects/fido2-8b943/notificationChannels/XXXX
```

`client_auth_failed`（5分 SUM > 10）・`login_failed`（5分 SUM > 20）・`http_5xx`（5分 SUM > 5）も同型で
`--condition-threshold-value` を変えて作成する。

## 何が done で何が残るか（正直）

- **done（コード, 本番稼働）**: アラート可能なセキュリティイベントの構造化 emit。request_id 相関（[Step3](./zero-trust-assessment.md)）。
- **done（本書, config 定義）**: 期待ベースライン・閾値・log-based metric/アラートポリシーの定義と実行 snippet。
- **残（ユーザ gate）**: 上記ポリシーの**実適用**（通知先選択が要る）。
- **残（Enterprise/Advanced, 対象外）**: 自動 first-pass triage・統計的異常検知・agentic SOAR・不変監査ログ。
