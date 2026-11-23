import CoreNFC
import ShojiCardKit
import ShojiProverKit
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
    @State private var proveReport = ""
    @State private var confirmProve = false
    @State private var benchReport = ""
    @State private var benchRunning = false
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

                Section("6. カードで証明を作る（端末内で完結）") {
                    Text("Mac から受け取ったリクエストに対し、カードの読み取り・署名・証明の生成をこの iPhone の中だけで行います。証明書は iPhone の外に出ません。Mac に渡すのは、証明と匿名ID だけです。上の暗証番号欄に署名用暗証番号を入力してください。")
                        .font(.footnote)
                    Button("リクエストを読み込んで証明を作る") { confirmProve = true }
                        .disabled(busy || benchRunning || password.isEmpty || attemptsLeft == nil)
                    if !proveReport.isEmpty {
                        Text(proveReport).font(.footnote.monospaced())
                    }
                }

                Section("5. 端末上で証明を生成する（計測）") {
                    Text("合成データ（モック証明書）で、この iPhone の中だけで証明を3回生成し、時間とメモリを測ります。カードも個人情報も使いません。")
                        .font(.footnote)
                    Button(benchRunning ? "計測中…" : "計測する") { runBenchmark() }
                        .disabled(benchRunning || busy)
                    if !benchReport.isEmpty {
                        Text(benchReport).font(.footnote.monospaced())
                    }
                }

                if !message.isEmpty {
                    Section("結果") { Text(message) }
                }

                Section("パスポート") {
                    NavigationLink("パスポートの構造確認") { PassportProbeView() }
                }

                // Always available, whatever state the app is in.
                Section("データの消去") {
                    Text("アプリ内に残っているもの（読み取った証明書、署名、Mac との受け渡し用ファイル、計測結果）をすべて消します。")
                        .font(.footnote)
                    Button("アプリ内のデータを消去", role: .destructive) {
                        wipe()
                        message = "消去しました。"
                    }
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
            .confirmationDialog(
                "カードの署名用の鍵で署名し、この iPhone で証明を作ります。暗証番号が間違っていると試行回数が1回減ります。",
                isPresented: $confirmProve, titleVisibility: .visible
            ) {
                Button("実行する") { proveOnDevice() }
                Button("やめる", role: .cancel) {}
            }
            .task {
                // `-shoji-bench` on the command line (used when driving the device from
                // the Mac) runs the benchmark immediately.
                if CommandLine.arguments.contains("-shoji-bench") { runBenchmark() }
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

    private static var requestFile: URL { documents.appendingPathComponent("request.json") }
    private static var submissionFile: URL { documents.appendingPathComponent("submission.json") }

    /// Card -> certificate + signature -> proof, all on this device. The certificate
    /// lives only in local variables here; it is never stored in view state, written
    /// to disk or offered for export.
    private func proveOnDevice() {
        proveReport = ""
        message = ""
        guard let request = try? Data(contentsOf: Self.requestFile),
            let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
            let challengeText = object["challenge"] as? String,
            let challenge = try? Challenge(challengeText)
        else {
            message = "リクエストのファイルがないか、形式が正しくありません。Mac から送ってください。"
            return
        }
        let pin = password
        busy = true
        try? FileManager.default.removeItem(at: Self.submissionFile)
        Task { @MainActor in
            defer {
                busy = false
                password = ""
            }
            do {
                let out = try await nfc.run(.certificateAndSignature(challenge: challenge, password: pin))
                attemptsLeft = out.attemptsLeft ?? attemptsLeft
                guard let certificate = out.signCertificate, let ca = out.caCertificate, let signature = out.signature else {
                    message = "カードから必要なデータを読み取れませんでした。"
                    return
                }
                proveReport = "証明を生成しています…"
                let submission = Self.submissionFile
                let report = await Task.detached(priority: .userInitiated) { () -> String in
                    do {
                        let material = try OnDeviceProver.loadMaterial()
                        let start = Date()
                        let proof = try Prover.prove(
                            circuit: material.circuit, certificate: certificate, caCertificate: ca,
                            signature: signature, request: request, srs: material.srs,
                            verificationKey: material.verificationKey)
                        let seconds = Date().timeIntervalSince(start)
                        func hex(_ d: Data?) -> String { "0x" + (d ?? Data()).map { String(format: "%02x", $0) }.joined() }
                        // The proof must be for this request, and the holder must meet the threshold.
                        guard proof.publicValue(1) == challenge.nonce, proof.publicValue(2) == challenge.appID else {
                            return "証明がリクエストと一致しません。"
                        }
                        guard proof.publicValue(6)?.last == 1 else {
                            return "証明は生成できましたが、年齢の条件を満たしていません。検証サーバは受理しません。"
                        }
                        // Exactly what the verifier is meant to see, and nothing else.
                        let body: [String: String] = [
                            "nonce": hex(challenge.nonce),
                            "ca_pubkey_hash": hex(proof.publicValue(0)),
                            "nullifier": hex(proof.publicValue(5)),
                            "proof": proof.proof.base64EncodedString(),
                        ]
                        try JSONSerialization.data(withJSONObject: body).write(to: submission, options: .atomic)
                        return String(
                            format: "証明を生成しました: %.2f 秒、%d バイト\n最大メモリ %.0f MiB\nMac から submission.json を取り出してください。",
                            seconds, proof.proof.count, OnDeviceProver.peakFootprintMiB())
                    } catch {
                        return "証明の生成に失敗しました: \(error)"
                    }
                }.value
                proveReport = report
                try? FileManager.default.removeItem(at: Self.requestFile)
            } catch {
                if case CardError.wrongPassword(let remaining) = error { attemptsLeft = remaining }
                message = describe(error)
            }
        }
    }

    private func runBenchmark() {
        benchRunning = true
        benchReport = ""
        Task.detached(priority: .userInitiated) {
            let (report, last) = OnDeviceProver.benchmark(runs: 3)
            // Also left in Documents so the Mac can collect them over the cable. The
            // proof is of synthetic data.
            let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            try? last?.proof.write(to: documents.appendingPathComponent("bench_proof"), options: .atomic)
            try? last?.publicInputs.write(to: documents.appendingPathComponent("bench_public_inputs"), options: .atomic)
            try? Data(report.utf8).write(to: documents.appendingPathComponent("bench.txt"), options: .atomic)
            await MainActor.run {
                benchReport = report
                benchRunning = false
            }
        }
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
            proveReport = ""
            benchReport = ""
            try? FileManager.default.removeItem(at: Self.documents.appendingPathComponent("passport"))
            for name in ["bench.txt", "bench_proof", "bench_public_inputs"] {
                try? FileManager.default.removeItem(at: Self.documents.appendingPathComponent(name))
            }
            try? FileManager.default.removeItem(at: Self.requestFile)
            try? FileManager.default.removeItem(at: Self.submissionFile)
            try? FileManager.default.removeItem(at: Self.challengeFile)
            try? FileManager.default.removeItem(at: Self.signatureFile)
        }
        password = ""
        message = ""
    }
}
