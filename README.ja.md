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
> 実カード1枚と iPhone 1台で一通り動かした。サービスの QR コードを読み取ってカードをかざすと、端末が証明を
> 生成して検証サーバに送り、本物の署名用CAだけを信頼する検証サーバが受理した。端末の外に出たのは証明と
> nullifier だけ。ただしローカルネットワーク上で開発用ビルドを動かしたもので、公開はしていない。
> 普段の開発にはモックCAを使う。
> 回路と依存ライブラリは監査を受けておらず、証明書の有効期限と失効は確認していない
> （[未確認事項](docs/ja/open-questions.md)）。

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

`testdata/` のモック鍵・証明書と `circuits/*/src/fixtures.nr` はリポジトリに含めていない。`make circuit` / `make test` が
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

回路（`circuits/card`）が証明すること:

1. TBSCertificate の SHA-256 に対する RSA-2048 署名が、`ca_pubkey_hash` に対応するCA鍵で検証できる。
2. 証明書内の利用者公開鍵で、`app_id` と `nonce` を含むメッセージへの署名が検証できる（カード所持）。
3. 証明書の生年月日と `current_date` から `age_threshold` 以上かを判定する。
4. `nullifier = Poseidon(Poseidon(利用者公開鍵), app_id)`。

公開鍵と生年月日の位置は証明者が指定するのではなく、回路が TBS の DER 構造を先頭から辿って決める
（`der.nr` / `cert.nr`。`unconstrained` なコードは自前では書いていない）。

サーバは公開入力のうち nullifier 以外をすべて自分の状態から組み立てる（`is_over_threshold` は 1 固定）。
保存するのは未使用の nonce と、アプリ別の nullifier・BANフラグだけ。

ウェブサービス向けに、検証サーバは**確認セッション**も提供する。サービスのページが QR コード
（`shoji://verify?u=<オリジン>&s=<セッション>`）を表示し、利用者がそれを読み取ると、ページは結果と nullifier を受け取る。
端末は通信相手のオリジンから `app_id` を自分で導くので、あるサービス向けの証明を別のサービスで使うことはできない。
また、日付が今日でない依頼は拒否する（サーバが日付を動かして生年月日を探ることを防ぐ）。
カードなしで同じ内容を証明する2つ目の回路（`circuits/delegated`）もある。カードは、利用者の端末が選んだ秘密の
コミットメントと、最長30日先の期限に1回だけ署名する。期限までは、端末がどのサービスに対しても、カードと同じ
nullifier で証明できる。AI エージェントのように利用者の代わりに動くソフトウェアのためのもので、エージェントを
何体動かしても、サービスからは同じ1人に見える。エージェントはリンクを利用者のウォレットに渡すだけで、証明書も委任も持たない。
代償（期限までは秘密がカードの代わりになる、ウォレットが利用者に代わって判断する）は[脅威モデル](docs/ja/threat-model.md)に書いた。
検証サーバは `-delegated-vk` を指定したときだけ、委任による証明を受け付ける。

`-public-origin` を指定して検証サーバを起動し、`/demo` を開くと試せる。
スマートフォンから接続できず（時間切れ）、同じアドレスにこのマシン自身からは接続できる場合は、マシンのファイアウォールを確認する。
macOS のファイアウォールは受信接続をプログラムごとに許可するので、ビルドし直した `verifier` は新しいプログラムとして、改めて許可が必要になる。
別のサービスが外から組み込む例として、架空のお店 [`examples/shop`](examples/shop/README.ja.md)（1人1点の限定販売と、購入者1人1件のレビュー）がある。エージェントからの注文も受け、同じ人のエージェント10体が買えるのは1点である（`examples/agent`）。

## ディレクトリ

```
circuits/          Noir回路とテスト（fixtures.nr は生成物、git管理外）
cmd/mockca/        モックCA（init / issue / hash）
cmd/genfixtures/   testdata と回路テスト用フィクスチャの生成
cmd/certinspect/   証明書の中身を出さずに構造だけを表示し、回路の想定と照合する
cmd/sodinspect/    IC 旅券の署名の構造を、中身を出さずに表示する
cmd/verifier/      検証サーバ（/challenge, /verify, ban サブコマンド）
cmd/mockclient/    利用者役（カードの代わりにモック鍵で署名）
cmd/cardclient/    実カード用の利用者役（チャレンジを取得し、カードの署名で証明を作る）
internal/proto/    回路とGoで一致させる値（メッセージ形式・ハッシュ・フィールド表現）
internal/mockjpki/ モック証明書の発行
internal/witness/  回路入力（Prover.toml）の組み立て
internal/prover/   noir-execute と bb prove の呼び出し
internal/verifier/ サーバ本体と SQLite ストア
internal/client/   利用者側のプロトコル処理
docs/              脅威モデル、未確認事項、ベンチマーク（日本語版は docs/ja/）
prover/            端末内で証明を生成する Rust ライブラリ（Noir と Barretenberg の公式クレートのみに依存）
examples/shop/     検証サーバを組み込む架空のお店（1人1点の購入、1人1件のレビュー）
examples/agent/    1人の代わりに買い物をするソフトウェア（何体でも動かせる）
cmd/wallet/        委任の流れでの利用者のスマートフォンの代役（委任に署名し、以後は鍵なしでリンクに答える）
ios/               iOS アプリ（QR コードからの確認、実カード、端末内の証明生成）と開発用ツール
```

## 文書

- [脅威モデル](docs/ja/threat-model.md)
- [未確認事項](docs/ja/open-questions.md)
- [ベンチマーク](docs/bench.md)（英語）
- [パスポート](docs/ja/passport.md): 日本のパスポートで同じことができるかの調査（回路は未実装）

## 性能

約22万ゲート、証明サイズ 14.7 KB。証明生成は Apple M5 のノートPCで約0.8秒（最大メモリ 585 MiB）、iPhone 15 Pro で約1.8秒（同 506 MiB）。検証は約10ミリ秒。

## 今後

いま動くもの: 回路、モックCA、検証サーバ、負のテスト、PC上のベンチマーク、確認セッションとデモページ、それを組み込むサービスの例（`examples/shop`）、モック証明書と PC での委任による証明、iOS アプリ（QR コードの読み取りから、実カードでの端末内の証明生成、受理まで）。

未実装のもの:

- 公開された検証サーバ（TLS、公開のオリジン）と、配布されたアプリ。いまはローカルネットワーク上で開発用ビルドを動かしただけ
- スマートフォンと実カードでの委任（アプリは委任の作成と保存に未対応。`prover/` はカードありの回路だけ）。どのエージェントに何を許すかをウォレットが決める方法は未設計
- 組み込むサービス向けの安定したインタフェース（`examples/shop` は、いまのセッションの2つのリクエストをそのまま使っている。nullifier は検証サーバのオリジンごとに決まるので、サービスごとに専用のオリジンが必要）と、セッションの QR コードを他人に読ませる攻撃への対策（脅威モデル参照）
- CA鍵のハッシュを端末上で計算すること（いまは検証サーバの一覧を中継して渡している）。信頼するCA鍵が複数になると必要
- Android と、今回試した機種よりメモリの少ない端末
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
