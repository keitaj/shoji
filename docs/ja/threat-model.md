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
| サービスが、別のサービスで通用する証明を端末に求める（そこでの nullifier を知る、または中継する） | 端末が通信相手のオリジンから `app_id` を導き、それ以外を拒否する | `testRefusesAnotherServicesAppID`, `testAppIDMatchesTheGoVector` |
| サービスが `current_date` を変えながら繰り返し確認させ、生年月日を探る | 端末は今日（±1日）でない日付を拒否し、カードを使う前に年齢の閾値を表示する | `testRefusesDatesThatAreNotToday` |
| リンクがインターネット上の平文 http サーバへ誘導する | http はローカルネットワークのアドレスに限り、警告つきで受け付ける | `testPlainHTTPOnlyOnTheLocalNetwork` |
| セッションの使い回し・放置 | 1セッションにつき結果は1つ。セッションには期限がある | `TestSessionReportsOutcomeToRelyingPage`, `TestSessionRules` |

各ネガティブテストは、通るケースから1点だけ変えたものにしている。改ざんしたTBSが構文上は正しく読めること
（＝止めているのが署名検証であること）は `tampered_date_of_birth_parses` / `substituted_public_key_parses` で確認している。

## 委任による証明（カードなし）

2つ目の回路（`circuits/delegated`）は、同じ内容をカードなしで証明する。カードは利用者の端末で1回だけ署名する。
署名の対象は、端末が選んだ秘密のコミットメントと、委任が有効な最後の日（最長30日先）である。
その日までは、証明書・その署名・秘密を知っている者が、どのサービスに対しても、カードと同じ nullifier で証明できる。
利用者の代わりに動くソフトウェア（AI エージェントなど）のためのもので、エージェントは確認用のリンクを
利用者のウォレットに渡すだけで、この3つのどれも見ない。

検証サーバは、設定された場合にだけ委任による証明を受け付け、委任だったかどうかをサービスに伝える。
ソフトウェアに何を許すかはサービスが決める（`examples/shop` は、1つの品だけエージェントからの注文を受ける）。

カードがある場合と比べて変わる点:

| 攻撃 | 対策 | テスト |
|---|---|---|
| 他人の証明書の写しと、自分の委任で証明する | 委任は、その証明書の中の鍵で署名されていなければならない | `fail_delegation_signed_by_another_key`, `TestDelegationFromAnotherCard` |
| 証明書と委任だけで、秘密を知らずに証明する | 署名されたコミットメントは Poseidon(秘密) で、証明者は秘密を知っている必要がある | `fail_wrong_secret` |
| 期限を過ぎた委任を使う、または期限を偽る | 期限は署名されたメッセージの一部で、`current_date` と比較される | `fail_expired`, `fail_claiming_a_later_expiry_than_signed`, `TestDelegationExpires` |
| 期限のない委任にカードで署名させる | 公開入力 `latest_expiry` を、検証サーバが「今日 + 30日」に設定する | `fail_longer_than_the_verifier_allows`, `TestDelegationLongerThanAllowed` |
| カードありの回路向けの署名を委任として使う（またはその逆） | 2つのメッセージは接頭辞も長さも異なる | `fail_card_present_signature_is_not_a_delegation` |
| 委任による証明を、別の nonce や別のサービスで使い回す | どちらも証明の公開入力 | `TestDelegatedProofIsBoundToItsNonce`, `TestDelegatedProofIsBoundToItsApp` |
| カードありのチャレンジに、委任による証明で答える | どちらの回路の証明を求めるかは、チャレンジと一緒に保存される | `TestProofMustMatchTheKindOfChallenge` |
| 1人が多数のエージェントを動かして、1人あたりの制限やBANを回避する | 同じ人のエージェントはすべて、その人のカードと同じ nullifier を持つ | `TestDelegatedProofIsTheSamePersonAsTheCard`, `TestDelegatedMinorAndBan`, `TestAgentsOfOnePersonGetOneItem` |

代償と、防げないもの:

- **秘密がカードの代わりになる。** ウォレットの中身（証明書、委任の署名、秘密）を写し取った者は、委任による証明を
  受け付けるすべてのサービスで、期限までその人として振る舞える。失効の仕組みは無く、歯止めは期限だけである。
  カードありの流れは毎回カードと暗証番号が要るが、こちらは1回で済む。
- **秘密は端末が選ばなければならない。** ソフトウェアが、自分の知っている秘密への委任にカードで署名させられるなら、
  30日間その人の身元を握ることになる。カードには区別がつかない。カードを操作するアプリは、自分で生成した秘密への
  委任にだけ署名させ、サーバから届いたものには決して署名させてはならない。カードありの流れのメッセージは
  固有の接頭辞を持つ固定の形式なので、サーバがその流れを通じて委任を得ることはできない。
- **ウォレットが証明書を保存する。** カードありの流れでは避けていたことである。スマートフォンでは、ハードウェアで
  保護された領域に置くべきもの。いまあるのは PC 上の代役（`cmd/wallet`）だけである。
- **ウォレットが利用者に代わって判断する。** 代役は、渡されたリンクすべてに答える。どのエージェントが、どのサービスに、
  どれだけ頼めるかを決めるのはウォレットの役目で、まだ設計していない。ウォレットに到達できるエージェントは、
  利用者の「1人1回」を好きな所で使えてしまう。
- 両方の種類の証明を見たサービスは、その人が委任を使っていることを知る。期限そのものは分からない（30日以内であることだけ）。

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
- **QR コードによるセッションの乗っ取り。** セッションを開いた者がその結果を受け取る。攻撃者が自分の QR コードを
  被害者に読み取らせると（フィッシングページなど）、攻撃者のセッションが被害者によって確認済みになる。
  端末はオリジンを表示するので偽サービスは見分けられるが、本物のサービスの QR コードを中継された場合は防げない。
  QR コードによるログイン全般の弱点で、対策していない。
- 今日の日付を正直に使うサービスでも、確認1回につき1ビットは知る。訪問のたびに年齢の閾値を変えることもできる。
  端末は閾値を表示するが、決まった値に限定はしていない。
- 信頼するCA鍵が複数あると、端末は自分のカードのハッシュがどれかを判別できない。その場合は推測せず拒否する。
- サーバはレート制限・呼び出し元アプリの認証・TLS を持たない（PoC）。`/challenge` は設定済みの app 名なら誰でも呼べる。
- nullifier のテーブルを見られる者は、あるアプリの利用者数は分かる。
- 端末側の証明生成ソフトが改ざんされていれば、個人情報の流出は防げない（オープンソースと再現可能ビルドで対処する領域）。端末内の証明生成（`prover/`）はソースからビルドし、Noir と Barretenberg の公式クレートだけに依存するが、Aztec が配布するビルド済みの Barretenberg 静的ライブラリ（チェックサム固定）をリンクしている。これは自分たちでビルドも監査もしていない。
- 証明書の構造は実カード1枚でしか確認していない。構造が異なるカード（たとえば TBSCertificate がバッファより長いもの）は回路が拒否する（誤って受理する方向ではない）。
