# shoji

[![CI](https://github.com/keitaj/shoji/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/keitaj/shoji/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/keitaj/shoji)](go.mod)
[![Noir 1.0.0](https://img.shields.io/badge/Noir-1.0.0-black)](circuits/Nargo.toml)
[![Status: proof of concept](https://img.shields.io/badge/status-proof%20of%20concept-orange)](docs/ja/threat-model.md)

[English](README.md) | **日本語**

> 障子のように「人間であるという輪郭は示すが、誰かは見せない」検証レイヤー。

マイナンバーカードの署名用電子証明書（JPKI）を信頼の起点に、証明書そのものをサーバへ渡さず、
「一定の年齢以上の実在する人間であること」と「アプリ別の匿名ID（nullifier）」をゼロ知識証明で示す、
オープンソースの検証レイヤー。

> [!WARNING]
> **現状は概念実証。本番利用はできない。**
> モックCAが発行した証明書で動作する。実カードの証明書構造は未確認で
> （[未確認事項](docs/ja/open-questions.md)）、回路と依存ライブラリは監査を受けておらず、
> 証明書の有効期限と失効は確認していない。

この文書は [README.md](README.md)（英語）の日本語版。内容が食い違う場合は英語版を正とする。

## 必要なツール（バージョン固定）

| ツール | バージョン | 備考 |
|---|---|---|
| nargo (Noir) | 1.0.0 | `noir-execute` も同梱物を使う |
| bb (Barretenberg) | 6.0.0 | UltraHonk、検証ターゲット `noir-recursive`（ZKあり） |
| Go | 1.27.4 | |

Noir の依存（`circuits/Nargo.toml` でタグ固定）: noir_rsa v0.12.1 / noir-bignum v0.11.0-1 / sha256 v0.3.0 / poseidon v0.4.0。
Go の依存は `go.mod` / `go.sum` で固定（go-iden3-crypto v0.0.17、modernc.org/sqlite v1.63.0）。

インストール（macOS arm64 の例。他のプラットフォームは同じリリースの該当アーカイブを使い、
リリースページの SHA-256 と照合する）:

```sh
curl -sSLO https://github.com/noir-lang/noir/releases/download/v1.0.0/noir-aarch64-apple-darwin.tar.gz
echo "ac2166fc06fe289fd2524f9eb9da228550159c976e88c1013bfc6d0e0b4a2309  noir-aarch64-apple-darwin.tar.gz" | shasum -a 256 -c
mkdir -p ~/.nargo/bin && tar -xzf noir-aarch64-apple-darwin.tar.gz -C ~/.nargo/bin

curl -sSLO https://github.com/AztecProtocol/aztec-packages/releases/download/v6.0.0/barretenberg-arm64-darwin.tar.gz
echo "48bd18a7d53781a2820e7538dfd89584ca5b4d76c7908e8be4910ce994e7c35e  barretenberg-arm64-darwin.tar.gz" | shasum -a 256 -c
mkdir -p ~/.bb && tar -xzf barretenberg-arm64-darwin.tar.gz -C ~/.bb
```

Makefile と Go のコードは PATH になければ `~/.nargo/bin` と `~/.bb` を探す。

## 使い方

```sh
make circuit      # 回路をコンパイルし検証鍵を circuits/target/vk に書き出す
make test         # 回路のテスト（nargo test）と Go のテスト（実際に証明を生成・検証する）
make bench        # 証明生成時間・メモリの計測

# 手元で一通り動かす
go run ./cmd/verifier -trusted-ca testdata/ca.pem -apps demo &
go run ./cmd/mockclient                                                    # 成人 → accepted
go run ./cmd/mockclient -cert testdata/minor.pem -key testdata/minor.key   # 未成年 → rejected
```

`testdata/` のモック鍵・証明書と `circuits/src/fixtures.nr` はリポジトリに含めていない。`make circuit` / `make test` が
初回に自動で生成し（`make fixtures`）、以後は再利用する。すべて合成データで、実在の個人の情報は含まない。

モックCAはテスト専用。モックCAの鍵を持つ者は任意の生年月日の証明書を発行できるので、
`testdata/ca.pem` を信頼する検証サーバを外部に公開しないこと。鍵をコミットしないのも同じ理由による。

## 仕組み

```
holder (端末)                                verifier (サーバ)
     │  POST /challenge {app}                      │
     │ ───────────────────────────────────────────▶│ nonce を発行・保存（短寿命・一回限り）
     │  {nonce, app_id, current_date, age_threshold}│
     │ ◀───────────────────────────────────────────│
 カードで "shoji-v1-nonce::" ‖ app_id ‖ nonce に署名
 証明書・署名をウィットネスに証明を生成
     │  POST /verify {nonce, ca_pubkey_hash,       │
     │               nullifier, proof}             │
     │ ───────────────────────────────────────────▶│ nonce を消費 → CA鍵ハッシュを信頼済みリストと照合
     │                                             │ → 公開入力を自分の値で組み立てて bb verify
     │  {ok, nullifier, new}                       │ → nullifier を記録（BAN確認）
     │ ◀───────────────────────────────────────────│
```

回路（`circuits/src`）が証明すること:

1. TBSCertificate の SHA-256 に対する RSA-2048 署名が、`ca_pubkey_hash` に対応するCA鍵で検証できる。
2. 証明書内の利用者公開鍵で、`app_id` と `nonce` を含むメッセージへの署名が検証できる（カード所持）。
3. 証明書の生年月日と `current_date` から `age_threshold` 以上かを判定する。
4. `nullifier = Poseidon(Poseidon(利用者公開鍵), app_id)`。

公開鍵と生年月日の位置は証明者が指定するのではなく、回路が TBS の DER 構造を先頭から辿って決める
（`der.nr` / `cert.nr`。`unconstrained` なコードは自前では書いていない）。

サーバは公開入力のうち nullifier 以外をすべて自分の状態から組み立てる（`is_over_threshold` は 1 固定）。
保存するのは未使用の nonce と、アプリ別の nullifier・BANフラグだけ。

## ディレクトリ

```
circuits/          Noir回路とテスト（fixtures.nr は生成物、git管理外）
cmd/mockca/        モックCA（init / issue / hash）
cmd/genfixtures/   testdata と回路テスト用フィクスチャの生成
cmd/verifier/      検証サーバ（/challenge, /verify, ban サブコマンド）
cmd/mockclient/    利用者役（カードの代わりにモック鍵で署名）
internal/proto/    回路とGoで一致させる値（メッセージ形式・ハッシュ・フィールド表現）
internal/mockjpki/ モック証明書の発行
internal/witness/  回路入力（Prover.toml）の組み立て
internal/prover/   noir-execute と bb prove の呼び出し
internal/verifier/ サーバ本体と SQLite ストア
internal/client/   利用者側のプロトコル処理
docs/              脅威モデル、未確認事項、ベンチマーク（日本語版は docs/ja/）
```

## 文書

- [脅威モデル](docs/ja/threat-model.md)
- [未確認事項](docs/ja/open-questions.md)
- [ベンチマーク](docs/bench.md)（英語）

## 性能

Apple M5 のノートPCで、約22万ゲート、証明生成 約0.8秒（最大メモリ 585 MiB）、検証 約10ミリ秒、証明サイズ 14.7 KB。
端末上での証明生成はまだ測っていない。

## 今後

いま動くもの: 回路、モックCA、検証サーバ、負のテスト、PC上のベンチマーク。実物のカードはまだ使っていない。

未実装のもの:

- 署名用電子証明書を NFC で読み出し、カードに nonce へ署名させる Android アプリ
- 回路を実カードの証明書構造に合わせること
- 端末上での証明生成
- 証明書の有効期限の確認

失効確認は公的個人認証の認定制度の対象のため、概念実証では扱わない。

## コントリビュート

回路の制約のレビューを特に歓迎する。先に [CONTRIBUTING.md](CONTRIBUTING.md) を読んでほしい。
最も重要な決まりは、**実在の個人の証明書・個人情報をコード・テストデータ・ログ・issue・コミットに含めない**こと。
脆弱性の報告は [SECURITY.md](SECURITY.md) の手順で。

## 免責

shoji は独立したプロジェクトで、J-LIS・デジタル庁その他の公的機関とは関係がなく、承認も受けていない。

## ライセンス

[Apache License 2.0](LICENSE)
