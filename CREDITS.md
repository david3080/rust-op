# Credits / Acknowledgements

rust-op は独立した Rust 実装です。**他プロジェクトのソースコードを複製してはいません。**
ただし、アーキテクチャの着想元・挙動の検証オラクル・参照実装として以下のオープンソース
プロジェクトに依拠しています。著作権法上の義務の有無にかかわらず、敬意と透明性のために謝辞を記します。

（依存クレートのライセンスは `Cargo.toml` / `Cargo.lock` および `deny.toml` で別途管理しています。
本ファイルは「設計の着想元・参照/オラクル」を対象とします。）

---

## node-oidc-provider — 設計（アーキテクチャ）の着想元

rust-op の Provider レジストリ設計は、node-oidc-provider の内部分解
（`actions` / `grants` / `client_auth` / `response_modes` / `adapters`）を**概念トレイト + 実装群**へ
写したものです（命名・コードはすべて独立した Rust 実装。ソースの逐語複製ではありません）。
コード中の「〜相当」というコメントはこの対応関係を示します。

- Project: https://github.com/panva/node-oidc-provider
- License: MIT

```
The MIT License (MIT)

Copyright (c) 2015 Filip Skokan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
```

## SimpleWebAuthn (@simplewebauthn/server) — WebAuthn / MDS3 の挙動オラクル・参照

rust-op の前身となった TypeScript 実装で用いており、FIDO2 Server Conformance / MDS3 対応の
**挙動オラクル（期待結果の確認）**として参照しました。ソースの複製はしていません。

- Project: https://github.com/MasterKale/SimpleWebAuthn
- Author: Matthew Miller (MasterKale)
- License: MIT

## webauthn-rs / webauthn-rs-core (Kanidm) — WebAuthn 検証の参照・オラクル

rust-op は WebAuthn 検証を RustCrypto でピュア Rust 自作する方針のため**採用していません**が、
設計比較および検証オラクルとして参照しました。ソースの複製はしていません。

- Project: https://github.com/kanidm/webauthn-rs
- License: MPL-2.0
- 注: MPL-2.0 のファイル単位コピーレフトは「当該 MPL ソースを改変して再配布する場合」に発生します。
  rust-op は webauthn-rs のソースを取り込んでいないため、本参照によって MPL-2.0 上の義務は生じません。

---

## 暗号・依存ライブラリ

rust-op は暗号プリミティブを **RustCrypto 系のクレート**に委譲する（OpenSSL/ring 非依存, `openssl = 0`）。
主要な暗号ライブラリと SPDX ライセンス:

| ライブラリ | 用途 | License |
|---|---|---|
| p256 / p384 | ECDSA (ES256/ES384), P-256/P-384 | Apache-2.0 OR MIT |
| rsa | RSA 検証 (RS256/RS1) | MIT OR Apache-2.0 |
| ed25519-dalek / curve25519-dalek | EdDSA (Ed25519) | BSD-3-Clause |
| sha2 / sha1 | SHA-256/384 / SHA-1 | MIT OR Apache-2.0 |
| ciborium | CBOR (COSE / attestation) | Apache-2.0 |
| x509-cert / der / spki / const-oid | X.509 証明書チェーン | Apache-2.0 OR MIT |
| ecdsa / signature / elliptic-curve / digest | 署名・曲線・ハッシュ抽象 | Apache-2.0 OR MIT |
| subtle | 定数時間比較 | BSD-3-Clause |
| base64 / zeroize | エンコード / ゼロ化 | MIT OR Apache-2.0 |

いずれもパーミッシブ（コピーレフト無し）で rust-op の MIT と互換。**実行時依存 全 crate** の完全な
一覧と SPDX ライセンスは [`THIRD-PARTY-LICENSES.md`](./THIRD-PARTY-LICENSES.md) を参照
（バイナリを第三者配布する場合は `cargo about` 等でライセンス全文・NOTICE まで含めて生成すること）。

---

## 標準仕様 / 検証ツール

- OpenID Connect Core / Discovery, FAPI 2.0, RFC 6749/7591/7636/8628/9101/9126/9207/9449/9470, WebAuthn (W3C), FIDO2 / MDS3 — 仕様の実装であり、これらは著作権で保護される「表現」ではなく公開仕様です。
- Kani (model checking) / proptest — テスト・検証に使用（依存として Cargo 管理）。
