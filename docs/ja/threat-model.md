# 脅威モデル

[English](../threat-model.md) | **日本語**（英語版を正とする）

## 守りたいもの

- 利用者の氏名・住所・生年月日・証明書・署名が端末の外に出ないこと。
- 検証者が「信頼するCAが発行した証明書のカードを今持っている、閾値以上の年齢の人」だけを受け入れること。
- 同じ人が同じアプリで複数の匿名IDを持てないこと。別のアプリの匿名IDと結びつかないこと。

## サーバに渡るもの・残るもの

| データ | 渡る | 保存 |
|---|---|---|
| 証明（約14.7KB、ZK） | ○ | × |
| nonce, app, current_date, age_threshold | サーバ発行 | nonce が消費されるか期限切れになるまで |
| ca_pubkey_hash | ○（どのCAかは分かる） | × |
| nullifier | ○ | ○（アプリ別、BANフラグ付き） |
| 証明書・4情報・署名・公開鍵 | × | × |

ログには受理・拒否の事実と理由の種別だけを出す。証明・nullifier・ウィットネスは出さない。
証明生成ツールの出力は捨て、Prover.toml とウィットネスは一時ディレクトリに作って終了時に消す。

## 攻撃と対策

| 攻撃 | 対策 | テスト |
|---|---|---|
| 自作CAで証明書を作る | CA鍵のハッシュが公開入力。サーバが自分の信頼済みリストと照合する | `fail_certificate_from_other_ca`, `fail_other_ca_key_with_trusted_hash`, `TestUntrustedCA` |
| 出回った証明書の写しで証明する | 証明書内の公開鍵による nonce への署名を回路で検証 | `fail_certificate_copy_without_card` |
| 過去の証明・署名の再利用 | nonce はサーバ発行・短寿命・一回限り。検証の前に消費する | `fail_nonce_mismatch`, `TestNonceIsSingleUse`, `TestNonceExpires`, `TestNonceNotIssuedByServer` |
| 別アプリ向けの署名・証明の流用 | 署名対象と公開入力に app_id を含める | `fail_app_id_mismatch`, `TestProofBoundToApp` |
| 生年月日の改ざん | TBS全体がCA署名の対象 | `fail_tampered_date_of_birth` |
| 別の属性に生年月日らしきバイト列を仕込む／抽出位置を偽る | 位置はウィットネスではなく、回路がDERを先頭から辿って決める | `decoy_date_of_birth_in_address_is_ignored`, `TestDecoyDateOfBirthIsRejected` |
| 日付や閾値を都合よく変えて証明する | 公開入力はサーバが保存した値で組み立てる | `TestMinorIsRejected` |
| 未成年が `is_over_threshold=0` の証明を出す | サーバは 1 を公開入力に固定する | `TestMinorIsRejected` |
| nullifier の差し替え・公開鍵の差し替え | nullifier は署名済みTBS内の公開鍵と app_id だけで決まる | `fail_substituted_public_key`, `TestNullifierCannotBeSubstituted` |
| BANされた人の再登録 | アプリ別 nullifier のBANフラグ | `TestBannedNullifier` |

各ネガティブテストは、通るケースから1点だけ変えたものにしている。改ざんしたTBSが構文上は正しく読めること
（＝止めているのが署名検証であること）は `tampered_date_of_birth_parses` / `substituted_public_key_parses` で確認している。

## 回路の制約について

- 証明者が自由に選べて、署名にもハッシュにも束縛されない入力は `ca_redc` / `user_redc`（Barrett 還元の補助値）だけ。
  noir-bignum の非制約計算のヒントで、誤った値では証明が作れないだけになる（`fail_bogus_redc_hint`）。
- RSA・SHA-256・Poseidon・多倍長演算は既存ライブラリを使い、自前では実装していない。DERの読み取りと
  バイト列のパックだけが自前で、すべて制約付きのコード。
- 公開指数は 65537 に固定。利用者鍵は SubjectPublicKeyInfo 全体を固定パターンと比較して RSA-2048 / e=65537 を強制する。
- 依存ライブラリ（特に noir-bignum の非制約ヒントと制約の対応）は自分では監査していない。

## 対象外・既知の限界

- 証明書の有効期限と失効を見ていない。期限切れ・失効済みのカードでも通る。
- 証明書の再発行で nullifier が変わる。証明書を持つ第三者は nullifier を計算できる（[open-questions.md](open-questions.md)）。
- カードと暗証番号を借りた・盗んだ場合は防げない。
- サーバはレート制限・呼び出し元アプリの認証・TLS を持たない（PoC）。`/challenge` は設定済みの app 名なら誰でも呼べる。
- nullifier のテーブルを見られる者は、あるアプリの利用者数は分かる。
- 端末側の証明生成ソフトが改ざんされていれば、個人情報の流出は防げない（オープンソースと再現可能ビルドで対処する領域）。端末内の証明生成（`prover/`）はソースからビルドし、Noir と Barretenberg の公式クレートだけに依存するが、Aztec が配布するビルド済みの Barretenberg 静的ライブラリ（チェックサム固定）をリンクしている。これは自分たちでビルドも監査もしていない。
- 証明書の構造は実カード1枚でしか確認していない。構造が異なるカード（たとえば TBSCertificate がバッファより長いもの）は回路が拒否する（誤って受理する方向ではない）。
