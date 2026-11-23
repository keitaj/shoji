# shoji card probe (iOS)

A development tool, not a product: it reads the JPKI certificates from a real
My Number Card so that their **structure** can be compared with the mock
certificates, using `cmd/certinspect` on your own Mac. It does not generate
proofs, has no network code, and keeps nothing after it leaves the foreground.

> [!CAUTION]
> - The signing password (6-16 letters and digits) **locks after 5 consecutive
>   wrong attempts** and can only be unlocked at a municipal office. The app sends
>   the password at most once per tap and refuses to send it when fewer than 3
>   attempts remain, but check what you type.
> - The signing certificate **is personal data** (name, address, date of birth,
>   gender). Keep it outside this repository, never commit it, never attach it to
>   an issue. Share only the redacted report printed by `certinspect`, after
>   reviewing it.
> - The card commands come from open-source implementations, not from an official
>   specification (see [docs/open-questions.md](../docs/open-questions.md)).

## Layout

```
ShojiCardKit/   card commands and safety rules, no CoreNFC dependency (Swift package with tests)
App/            SwiftUI app and the CoreNFC transport
project.yml     XcodeGen spec for the Xcode project
```

## Requirements

- Xcode (the Command Line Tools alone cannot build an iOS app or run the tests)
- An iPhone with NFC, and an Apple developer team that can sign apps using the
  *NFC Tag Reading* capability
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`

## Build and install

```sh
cd ios
(cd ShojiCardKit && swift test)   # card-command logic against a fake card
xcodegen generate
open ShojiProbe.xcodeproj
```

In Xcode: select the *ShojiProbe* target, choose your team under *Signing &
Capabilities*, connect the iPhone and run.

## Use

1. **Read without the password.** Reads the signing CA certificate and the
   number of password attempts left. No password is sent, so this step cannot
   lock anything; use it to confirm that NFC works.
2. **Read the signing certificate.** Enter the signing password, confirm, and tap
   the card again.
3. **Hand the files to your own Mac** (AirDrop), into a directory outside the
   repository, then:

   ```sh
   go run ./cmd/certinspect -cert ~/jpki-real/jpki_sign.der -ca ~/jpki-real/jpki_sign_ca.der
   ```

4. Delete the files when done (`rm -P` or just `rm`), and use *erase* in the app.
