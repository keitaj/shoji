import CoreNFC
import ShojiCardKit
import SwiftUI

/// A development tool for checking the structure of a real JPKI signing
/// certificate. It reads certificates from the card and lets the developer hand
/// them to `cmd/certinspect` on their own machine. It has no network code and
/// writes nothing except the temporary files the developer explicitly exports.
struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase

    @State private var password = ""
    @State private var attemptsLeft: Int?
    @State private var caCertificate: Data?
    @State private var signCertificate: Data?
    @State private var exported: [URL] = []
    @State private var message = ""
    @State private var busy = false
    @State private var confirmPassword = false
    @State private var challengeText = ""
    @State private var signatureHex = ""
    @State private var confirmSign = false
    @State private var nfc = NFCCardSession()

    var body: some View {
        NavigationStack {
            Form {
                Section("1. 暗証番号なしで読む") {
                    Text("署名用CA証明書と、署名用暗証番号の残り試行回数を読みます。暗証番号は送りません。")
                        .font(.footnote)
                    Button("カードを読む（暗証番号なし）") { run(.withoutPassword) }
                        .disabled(busy)
                    if let attemptsLeft {
                        LabeledContent("残り試行回数", value: "\(attemptsLeft) 回")
                    }
                    if let caCertificate {
                        LabeledContent("CA証明書", value: "\(caCertificate.count) バイト")
                    }
                }

                Section("2. 署名用電子証明書を読む") {
                    Text("署名用電子証明書には氏名・住所・生年月日・性別が含まれます。暗証番号（英数字6〜16桁）は5回連続で間違えるとロックされ、解除は市区町村の窓口でしかできません。このアプリは1回の読み取りで暗証番号を1度しか送らず、残りが3回未満のときは送りません。")
                        .font(.footnote)
                    SecureField("署名用暗証番号", text: $password)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                    Button("暗証番号を使って読む") { confirmPassword = true }
                        .disabled(busy || password.isEmpty || attemptsLeft == nil)
                    if attemptsLeft == nil {
                        Text("先に 1 を実行して、残り試行回数を確認してください。").font(.footnote)
                    }
                    if let signCertificate {
                        LabeledContent("署名用電子証明書", value: "\(signCertificate.count) バイト")
                    }
                }

                if caCertificate != nil || signCertificate != nil {
                    Section("3. 自分の Mac に渡す") {
                        Text("AirDrop などで自分の Mac に渡し、リポジトリの外に置いて certinspect にかけます。署名用電子証明書は個人情報です。他人やクラウドに渡さないでください。")
                            .font(.footnote)
                        if exported.isEmpty {
                            Button("書き出す準備をする") { prepareExport() }
                        } else {
                            ShareLink(items: exported) { Text("共有シートを開く") }
                        }
                        Button("読み取ったデータを消去", role: .destructive) { wipe() }
                    }
                }

                Section("4. チャレンジに署名する") {
                    Text("Mac の cardclient challenge が表示した文字列（shoji1:…）を貼り付けます。カードの署名用の鍵で、shoji の本人確認用メッセージ（アプリIDと使い捨ての値）に署名します。それ以外のデータには署名しません。上の暗証番号欄に署名用暗証番号を入力してください。")
                        .font(.footnote)
                    TextField("shoji1:…", text: $challengeText, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.footnote.monospaced())
                        .lineLimit(3...6)
                    Button("Mac から受け取ったチャレンジを読み込む") { loadChallengeFile() }
                    Button("クリップボードから貼り付け") { challengeText = UIPasteboard.general.string ?? "" }
                    Button("署名する") { confirmSign = true }
                        .disabled(busy || password.isEmpty || attemptsLeft == nil || (try? Challenge(challengeText)) == nil)
                    if !challengeText.isEmpty && (try? Challenge(challengeText)) == nil {
                        Text("チャレンジの形式が正しくありません。").font(.footnote)
                    }
                    if !signatureHex.isEmpty {
                        LabeledContent("署名", value: "\(signatureHex.count / 2) バイト")
                        Text("署名はアプリの書類フォルダ（signature.txt）にも保存しました。Mac からケーブル経由で取り出せます。")
                            .font(.footnote)
                        Button("署名をコピー") { UIPasteboard.general.string = signatureHex }
                    }
                }

                if !message.isEmpty {
                    Section("結果") { Text(message) }
                }
            }
            .navigationTitle("shoji card probe")
            .confirmationDialog(
                "暗証番号をカードに送ります。間違っていると試行回数が1回減ります。",
                isPresented: $confirmPassword, titleVisibility: .visible
            ) {
                Button("送る") { run(.signCertificate(password: password)) }
                Button("やめる", role: .cancel) {}
            }
            .confirmationDialog(
                "カードの署名用の鍵で署名します。暗証番号が間違っていると試行回数が1回減ります。",
                isPresented: $confirmSign, titleVisibility: .visible
            ) {
                Button("署名する") {
                    if let challenge = try? Challenge(challengeText) {
                        run(.sign(challenge: challenge, password: password))
                    }
                }
                Button("やめる", role: .cancel) {}
            }
            .onChange(of: scenePhase) { phase in
                // Nothing personal stays around once the app leaves the foreground. The
                // challenge and signature files are kept (they hold no personal data and
                // the Mac may still need to collect the signature) until "erase".
                if phase == .background { wipe(keepHandOffFiles: true) }
            }
        }
    }

    private func run(_ job: NFCCardSession.Job) {
        busy = true
        message = ""
        Task { @MainActor in
            defer {
                busy = false
                password = ""
            }
            do {
                let out = try await nfc.run(job)
                attemptsLeft = out.attemptsLeft ?? attemptsLeft
                caCertificate = out.caCertificate ?? caCertificate
                signCertificate = out.signCertificate ?? signCertificate
                if let signature = out.signature {
                    signatureHex = signature.map { String(format: "%02x", $0) }.joined()
                    challengeText = ""
                    try? FileManager.default.removeItem(at: Self.challengeFile)
                    try? Data(signatureHex.utf8).write(to: Self.signatureFile, options: [.atomic, .completeFileProtection])
                }
                removeExportedFiles()
                message = "読み取りました。"
            } catch {
                if case CardError.wrongPassword(let remaining) = error { attemptsLeft = remaining }
                message = describe(error)
            }
        }
    }

    private func describe(_ error: Error) -> String {
        switch error {
        case CardError.passwordFormat:
            return "暗証番号は英数字6〜16桁です。カードには何も送っていません。"
        case CardError.tooFewAttemptsLeft(let remaining):
            return "残り試行回数が \(remaining) 回のため、暗証番号を送りませんでした。ロックを避けるため、このアプリは残り3回未満では試しません。"
        case CardError.wrongPassword(let remaining):
            return "暗証番号が違います。残り \(remaining) 回です。続けて試さず、暗証番号を確認してください。"
        case CardError.status(let step, let sw):
            return "カードが想定外の応答を返しました（\(step): \(String(format: "%04X", sw))）。"
        case CardError.unexpectedData(let what):
            return "読み取ったデータが想定と違います（\(what)）。"
        case SessionError.nfcUnavailable:
            return "この端末では NFC の読み取りが使えません。"
        case SessionError.notACard:
            return "対応していないカードです。"
        case let e as NFCReaderError where e.code == .readerSessionInvalidationErrorUserCanceled:
            return "キャンセルしました。"
        default:
            return "読み取りに失敗しました。カードを当て直してください。"
        }
    }

    // Hand-off with the developer's Mac over the cable (`xcrun devicectl device copy`):
    // the Mac puts challenge.txt into the app's Documents folder and collects
    // signature.txt from it. Neither file contains personal data.
    private static var documents: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
    private static var challengeFile: URL { documents.appendingPathComponent("challenge.txt") }
    private static var signatureFile: URL { documents.appendingPathComponent("signature.txt") }

    private func loadChallengeFile() {
        guard let data = try? Data(contentsOf: Self.challengeFile), let text = String(data: data, encoding: .utf8) else {
            message = "チャレンジのファイルがありません。Mac から送ってください。"
            return
        }
        challengeText = text.trimmingCharacters(in: .whitespacesAndNewlines)
        message = (try? Challenge(challengeText)) == nil ? "受け取ったチャレンジの形式が正しくありません。" : "チャレンジを読み込みました。"
    }

    private func prepareExport() {
        removeExportedFiles()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("shoji-probe", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var urls: [URL] = []
        for (name, data) in [("jpki_sign_ca.der", caCertificate), ("jpki_sign.der", signCertificate)] {
            guard let data else { continue }
            let url = dir.appendingPathComponent(name)
            do {
                try data.write(to: url, options: [.atomic, .completeFileProtection])
                urls.append(url)
            } catch {
                message = "書き出しに失敗しました。"
            }
        }
        exported = urls
    }

    private func removeExportedFiles() {
        for url in exported { try? FileManager.default.removeItem(at: url) }
        exported = []
    }

    private func wipe(keepHandOffFiles: Bool = false) {
        removeExportedFiles()
        caCertificate = nil
        signCertificate = nil
        signatureHex = ""
        challengeText = ""
        if !keepHandOffFiles {
            try? FileManager.default.removeItem(at: Self.challengeFile)
            try? FileManager.default.removeItem(at: Self.signatureFile)
        }
        password = ""
        message = ""
    }
}
