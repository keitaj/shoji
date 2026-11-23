# shoji for iOS

Two things in one app:

- **Verification** (the main screen): opened from a service's QR code
  (`shoji://verify?u=<origin>&s=<session>`), it shows who is asking and what
  will be disclosed, reads the card with one tap, generates the proof on the
  phone and sends it to that service's verifier. Only the proof and the
  nullifier leave the phone.
- **Developer tools** (button at the top right): read the JPKI certificates from
  a real card so that their **structure** can be compared with the mock
  certificates using `cmd/certinspect`, sign a challenge for a proof made on a
  Mac, prove on the device from a request relayed over the cable, and benchmark
  on-device proving.

The app's only network code is `App/VerifierClient.swift`: two requests to the
origin named by the link. It keeps no certificate after a verification.

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
ShojiCardKit/    card commands and safety rules, no CoreNFC dependency (Swift package with tests)
ShojiProverKit/  Swift wrapper around the in-process prover in ../prover
App/             SwiftUI app and the CoreNFC transport
scripts/         prepare-resources.sh: circuit, verification key and reference string for the app
project.yml      XcodeGen spec for the Xcode project
```

## Requirements

- Xcode (the Command Line Tools alone cannot build an iOS app or run the tests)
- An iPhone with NFC, and an Apple developer team that can sign apps using the
  *NFC Tag Reading* capability
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- A Rust toolchain with the iOS targets, for the prover:
  `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`

## Build and install

```sh
make circuit                              # in the repository root
prover/scripts/build-apple.sh             # builds ios/ShojiProverKit/ShojiProverFFI.xcframework
ios/scripts/prepare-resources.sh          # fills ios/App/ProverResources/

cd ios
(cd ShojiCardKit && swift test)           # card-command logic against a fake card
cp Local.xcconfig.example Local.xcconfig  # then set your team identifier in it
xcodegen generate
open ShojiProbe.xcodeproj
```

Connect the iPhone and run. `Local.xcconfig` keeps your team identifier out of
the repository and across `xcodegen generate`.

## Verify with a service

Start a verifier with a public origin the phone can reach and open its demo page
(see the repository README). Scan the QR code with the iPhone camera, check the
request, enter the signing password and tap the card. For a verifier on the same
network over plain http, iOS asks once for permission to use the local network;
the first attempt can fail until it is granted.

The phone refuses a request whose `app_id` is not the one of the origin it is
talking to, whose date is not today, or which comes over plain http from outside
the local network.

## Developer tools

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

4. **Sign a challenge** (to make a full proof with the real card). Start a
   verifier that trusts the card's CA certificate, get a challenge and copy it
   into the app over the cable:

   ```sh
   go run ./cmd/verifier -trusted-ca ~/jpki-real/jpki_sign_ca.der -apps demo -nonce-ttl 30m -db ~/jpki-real/shoji.db

   go run ./cmd/cardclient challenge -state ~/jpki-real/challenge.json > ~/jpki-real/challenge.txt
   xcrun devicectl device copy to --device <device> \
       --domain-type appDataContainer --domain-identifier io.github.keitaj.shoji.probe \
       --source ~/jpki-real/challenge.txt --destination Documents/challenge.txt
   ```

   In the app: read the retry counter (step 1), enter the signing password, load
   the challenge, sign. Then collect the signature and prove:

   ```sh
   xcrun devicectl device copy from --device <device> \
       --domain-type appDataContainer --domain-identifier io.github.keitaj.shoji.probe \
       --source Documents/signature.txt --destination ~/jpki-real/signature.txt
   go run ./cmd/cardclient prove -state ~/jpki-real/challenge.json \
       -cert ~/jpki-real/jpki_sign.der -ca ~/jpki-real/jpki_sign_ca.der < ~/jpki-real/signature.txt
   ```

   `xcrun devicectl list devices` shows the device identifier. The app signs only
   shoji's own nonce message, rebuilt from the challenge; it cannot be made to
   sign an arbitrary digest. Pasting the challenge and copying the signature
   through the clipboard also works where Universal Clipboard does.
5. **Prove on the device.** This is the intended design: the certificate never
   leaves the phone.

   ```sh
   go run ./cmd/cardclient challenge -state ~/jpki-real/challenge.json -request ~/jpki-real/request.json
   xcrun devicectl device copy to --device <device> \
       --domain-type appDataContainer --domain-identifier io.github.keitaj.shoji.probe \
       --source ~/jpki-real/request.json --destination Documents/request.json
   ```

   In the app: read the retry counter (step 1), enter the signing password, then
   "prove with the card". One tap reads the certificate and signs; the proof is
   generated on the phone. Collect the result, which holds only the nonce, the
   CA key hash, the nullifier and the proof, and relay it:

   ```sh
   xcrun devicectl device copy from --device <device> \
       --domain-type appDataContainer --domain-identifier io.github.keitaj.shoji.probe \
       --source Documents/submission.json --destination ~/jpki-real/submission.json
   go run ./cmd/cardclient submit -state ~/jpki-real/challenge.json -submission ~/jpki-real/submission.json
   ```

   With this flow, steps 2 to 4 (exporting the certificate, proving on the Mac)
   are not needed.
6. **Benchmark** on-device proving with the bundled mock inputs (no card involved).
7. Use *erase* at the bottom of the app when done, and delete any exported files.
