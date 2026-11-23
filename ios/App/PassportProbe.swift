import CoreNFC
import ShojiCardKit
import SwiftUI

/// Developer tool: reads the parts of an electronic passport that describe how it
/// is signed, so their structure can be examined on the developer's Mac with
/// `cmd/sodinspect`. It reads the security object, the chip's public keys and one
/// Active Authentication signature. It does not read the photo (DG2) or the MRZ
/// data group (DG1).
final class PassportSession: NSObject, NFCTagReaderSessionDelegate {
    struct Output {
        var files: [String: Data] = [:]
        var notes: [String] = []
    }

    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<Output, Error>?
    private var mrz: MRZKey?

    func run(mrz: MRZKey) async throws -> Output {
        guard NFCTagReaderSession.readingAvailable else { throw SessionError.nfcUnavailable }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            self.mrz = mrz
            let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: .main)
            session?.alertMessage = "パスポートの顔写真ページを開き、iPhone の上部に当ててください"
            self.session = session
            session?.begin()
        }
    }

    private func finish(_ result: Result<Output, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        self.session = nil
        continuation.resume(with: result)
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        finish(.failure(error))
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1, case .iso7816(let tag) = tags[0], let mrz else {
            finish(.failure(SessionError.notACard))
            session.invalidate(errorMessage: "パスポートを1冊だけ当ててください")
            return
        }
        Task { @MainActor in
            do {
                try await session.connect(to: tags[0])
                let passport = PassportCard(transport: NFCTransport(tag: tag))
                var out = Output()

                try await passport.selectApplication()
                let sm = try await passport.basicAccessControl(mrz: mrz)

                session.alertMessage = "読み取っています。動かさないでください…"
                out.files["com.bin"] = try await passport.readFile(.com, sm)
                out.files["sod.bin"] = try await passport.readFile(.sod, sm)
                // DG15, Active Authentication and DG14 are optional in the standard. A failed
                // command usually ends secure messaging, so stop at the first failure and keep
                // what was read. DG14 comes last because it is the most likely to be absent.
                do {
                    out.files["dg15.bin"] = try await passport.readFile(.dg15, sm)
                    let nonce = PassportCard<NFCTransport>.systemRandom(8)
                    out.files["aa_signature.bin"] = try await passport.activeAuthentication(nonce: nonce, sm)
                    out.files["aa_nonce.bin"] = nonce
                    out.files["dg14.bin"] = try await passport.readFile(.dg14, sm)
                } catch PassportError.status(let step, let sw) {
                    out.notes.append("\(step): \(String(format: "%04X", sw))（以降の読み取りを中止）")
                }

                session.alertMessage = "読み取りが完了しました"
                self.finish(.success(out))
                session.invalidate()
            } catch {
                self.finish(.failure(error))
                session.invalidate(errorMessage: "読み取りに失敗しました")
            }
        }
    }
}

struct PassportProbeView: View {
    @State private var documentNumber = ""
    @State private var dateOfBirth = ""
    @State private var dateOfExpiry = ""
    @State private var report = ""
    @State private var busy = false
    @State private var reader = PassportSession()

    private static var directory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("passport", isDirectory: true)
    }

    var body: some View {
        Form {
            Section("顔写真ページの記載") {
                Text("パスポートのチップは、顔写真ページに印刷された3つの項目から作る鍵でしか読めません。入力した値は読み取りにだけ使い、保存しません。")
                    .font(.footnote)
                TextField("旅券番号（例: TK1234567）", text: $documentNumber)
                    .textInputAutocapitalization(.characters).autocorrectionDisabled()
                TextField("生年月日（YYMMDD）", text: $dateOfBirth).keyboardType(.numberPad)
                TextField("有効期間満了日（YYMMDD）", text: $dateOfExpiry).keyboardType(.numberPad)
            }
            Section {
                Text("読むのは、発行国の署名の領域、チップの公開鍵、チップによる署名1つです。顔写真と、氏名などの入った領域は読みません。間違った値を入れても、チップがロックされることはありません。")
                    .font(.footnote)
                Button(busy ? "読み取り中…" : "パスポートを読む") { read() }
                    .disabled(busy || documentNumber.isEmpty || dateOfBirth.count != 6 || dateOfExpiry.count != 6)
                Button("読み取ったファイルを消去", role: .destructive) { erase() }
            }
            if !report.isEmpty {
                Section("結果") { Text(report).font(.footnote.monospaced()) }
            }
        }
        .navigationTitle("パスポートの構造確認")
    }

    private func read() {
        guard let mrz = try? MRZKey(documentNumber: documentNumber, dateOfBirth: dateOfBirth, dateOfExpiry: dateOfExpiry) else {
            report = "入力の形式が正しくありません。"
            return
        }
        busy = true
        report = ""
        Task { @MainActor in
            defer { busy = false }
            do {
                let out = try await reader.run(mrz: mrz)
                erase()
                try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true)
                var lines: [String] = []
                for (name, data) in out.files.sorted(by: { $0.key < $1.key }) {
                    try data.write(to: Self.directory.appendingPathComponent(name), options: [.atomic, .completeFileProtection])
                    lines.append("\(name): \(data.count) バイト")
                }
                lines.append(contentsOf: out.notes)
                lines.append("Mac からケーブル経由で取り出してください。")
                report = lines.joined(separator: "\n")
                documentNumber = ""
                dateOfBirth = ""
                dateOfExpiry = ""
            } catch PassportError.accessDenied {
                report = "チップが鍵を受け付けませんでした。旅券番号・生年月日・有効期間満了日を確認してください。"
            } catch PassportError.status(let step, let sw) {
                report = "チップが想定外の応答を返しました（\(step): \(String(format: "%04X", sw))）。"
            } catch PassportError.secureMessaging(let what) {
                report = "暗号化通信の検査に失敗しました（\(what)）。"
            } catch PassportError.unexpectedData(let what) {
                report = "読み取ったデータが想定と違います（\(what)）。"
            } catch let e as NFCReaderError where e.code == .readerSessionInvalidationErrorUserCanceled {
                report = "キャンセルしました。"
            } catch {
                report = "読み取りに失敗しました。パスポートを当て直してください。"
            }
        }
    }

    private func erase() {
        try? FileManager.default.removeItem(at: Self.directory)
        if !busy { report = "" }
    }
}
