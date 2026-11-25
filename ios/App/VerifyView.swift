import CoreNFC
import ShojiCardKit
import ShojiProverKit
import SwiftUI

/// The screen an end user sees: a service asks, the user consents, taps the card,
/// and the phone proves and answers. The certificate exists only in local
/// variables of `run()` for the duration of one verification.
struct VerifyView: View {
    /// Set when the app is opened from a service's QR code or link.
    @Binding var link: VerificationLink?

    enum Phase: Equatable {
        case idle
        case loading
        case ready(VerificationRequest)
        case working(String)
        case done(isNew: Bool, nullifier: String)
        case failed(String)
    }

    @State private var phase: Phase = .idle
    @State private var password = ""
    @State private var showDeveloperTools = false
    @State private var nfc = NFCCardSession()

    var body: some View {
        NavigationStack {
            Form {
                switch phase {
                case .idle:
                    Section {
                        Text("サービスの画面に表示された QR コードを、iPhone のカメラで読み取ってください。")
                        Text("このアプリは、あなたが一定の年齢以上の実在する人であることだけを、マイナンバーカードを使って証明します。氏名・住所・生年月日はサービスに伝わりません。")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                case .loading:
                    Section { ProgressView("サービスに問い合わせています…") }
                case .ready(let request):
                    if let link { consent(link: link, request: request) }
                case .working(let text):
                    Section { ProgressView(text) }
                case .done(let isNew, let nullifier):
                    Section("確認が完了しました") {
                        Label("サービスに証明を送りました", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                        Text(isNew ? "このサービスでは初めての確認です。" : "このサービスでは以前にも確認しています。")
                        LabeledContent("このサービスでのあなたの匿名ID") {
                            Text(nullifier.prefix(14) + "…").font(.footnote.monospaced())
                        }
                        Text("サービスに伝わったのは、条件を満たすことと、この匿名ID だけです。")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Section { Button("閉じる") { reset() } }
                case .failed(let text):
                    Section("確認できませんでした") {
                        Text(text)
                    }
                    Section {
                        if link != nil { Button("もう一度試す") { Task { await load() } } }
                        Button("やめる", role: .cancel) { reset() }
                    }
                }
            }
            .navigationTitle("shoji")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("開発用ツール") { showDeveloperTools = true }.font(.footnote)
                }
            }
            .sheet(isPresented: $showDeveloperTools) { ContentView() }
            .task(id: link) { if link != nil { await load() } }
        }
    }

    @ViewBuilder
    private func consent(link: VerificationLink, request: VerificationRequest) -> some View {
        Section("確認の依頼") {
            LabeledContent("依頼元", value: link.host)
            if link.isInsecure {
                Label("暗号化されていない接続です（開発用）。", systemImage: "exclamationmark.triangle")
                    .font(.footnote).foregroundStyle(.orange)
            }
            Text("このサービスに、次の2つだけを伝えます。")
            Label("あなたが \(request.ageThreshold) 歳以上の実在する人であること", systemImage: "person.fill.checkmark")
            Label("このサービス専用の匿名ID", systemImage: "number")
            Text("氏名・住所・生年月日・カードの情報は伝えません。匿名ID は他のサービスのものとは結びつきません。")
                .font(.footnote).foregroundStyle(.secondary)
        }
        Section("署名用電子証明書の暗証番号") {
            SecureField("英数字6〜16桁", text: $password)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
            Text("5回連続で間違えるとロックされます。残りが3回未満のときは、このアプリは暗証番号を送りません。")
                .font(.footnote).foregroundStyle(.secondary)
        }
        Section {
            Button("カードをかざして確認する") { Task { await run(link: link, request: request) } }
                .disabled(password.isEmpty)
            Button("やめる", role: .cancel) { reset() }
        }
    }

    private func reset() {
        password = ""
        link = nil
        phase = .idle
    }

    /// Asks the service what it wants and checks the request before showing it.
    private func load() async {
        guard let link else { return }
        phase = .loading
        do {
            let c = try await VerifierClient(link: link).challenge()
            let request = try VerificationRequest(
                link: link, appID: c.app_id, nonce: c.nonce, currentDate: c.current_date,
                ageThreshold: c.age_threshold, trustedCAHashes: c.trusted_ca_hashes,
                today: VerificationRequest.todayInJapan())
            phase = .ready(request)
        } catch {
            phase = .failed(describe(error))
        }
    }

    private func run(link: VerificationLink, request: VerificationRequest) async {
        let pin = password
        password = ""
        do {
            phase = .working("カードを読み取っています…")
            let out = try await nfc.run(.certificateAndSignature(challenge: request.challenge, password: pin))
            guard let certificate = out.signCertificate, let ca = out.caCertificate, let signature = out.signature else {
                phase = .failed("カードから必要なデータを読み取れませんでした。")
                return
            }

            phase = .working("証明を作成しています…")
            let requestJSON = try request.proverRequestJSON()
            let proof = try await Task.detached(priority: .userInitiated) {
                let material = try OnDeviceProver.loadMaterial()
                return try Prover.prove(
                    circuit: material.circuit, certificate: certificate, caCertificate: ca, signature: signature,
                    request: requestJSON, srs: material.srs, verificationKey: material.verificationKey)
            }.value

            // The proof must answer this request, and nothing is sent unless the
            // condition is met: a failing proof would only tell the service "no".
            guard proof.publicValue(1) == request.challenge.nonce, proof.publicValue(2) == request.challenge.appID else {
                phase = .failed("作成した証明が依頼と一致しませんでした。")
                return
            }
            guard proof.publicValue(6)?.last == 1 else {
                phase = .failed("年齢の条件を満たしていないため、証明は送りませんでした。")
                return
            }

            phase = .working("サービスに証明を送っています…")
            func hex(_ d: Data?) -> String { "0x" + (d ?? Data()).map { String(format: "%02x", $0) }.joined() }
            let result = try await VerifierClient(link: link).verify(
                nonce: hex(request.challenge.nonce), caPubkeyHash: hex(proof.publicValue(0)),
                nullifier: hex(proof.publicValue(5)), proof: proof.proof)
            phase = .done(isNew: result.new, nullifier: result.nullifier)
        } catch {
            phase = .failed(describe(error))
        }
    }

    private func describe(_ error: Error) -> String {
        switch error {
        case VerifierClient.ClientError.unreachable(let reason):
            return "サービスに接続できませんでした。通信環境を確認してください。（\(reason)）"
        case VerifierClient.ClientError.rejected(_, let message):
            switch message {
            case "unknown session": return "この QR コードは期限切れか、すでに使われています。サービスの画面を更新してやり直してください。"
            case "unknown, used or expired nonce": return "時間がかかりすぎたため、依頼の期限が切れました。もう一度試してください。"
            case "untrusted CA": return "このサービスは、このカードの認証局を受け付けていません。"
            case "banned": return "このサービスでは利用が停止されています。"
            case "invalid proof": return "サービスが証明を受け付けませんでした。"
            default: return "サービスがエラーを返しました。"
            }
        case VerifierClient.ClientError.malformedResponse:
            return "サービスの応答を読み取れませんでした。"
        case VerificationRequest.CheckError.wrongApplication:
            return "このサービスは、別のサービス向けの証明を求めました。安全のため中止しました。"
        case VerificationRequest.CheckError.wrongDate:
            return "サービスが示した日付が今日と一致しません。安全のため中止しました。"
        case VerificationRequest.CheckError.unsupportedThreshold, VerificationRequest.CheckError.malformed,
            VerificationRequest.CheckError.ambiguousCA:
            return "このサービスの依頼には対応していません。"
        case CardError.passwordFormat:
            return "暗証番号は英数字6〜16桁です。カードには何も送っていません。"
        case CardError.tooFewAttemptsLeft(let remaining):
            return "暗証番号の残り試行回数が \(remaining) 回のため、カードに送りませんでした。市区町村の窓口で暗証番号の再設定をしてください。"
        case CardError.wrongPassword(let remaining):
            return "暗証番号が違います。残り \(remaining) 回です。確認してからやり直してください。"
        case CardError.status, CardError.unexpectedData:
            return "カードが想定外の応答を返しました。対応していないカードの可能性があります。"
        case SessionError.nfcUnavailable:
            return "この端末では NFC の読み取りが使えません。"
        case SessionError.notACard:
            return "対応していないカードです。"
        case let e as NFCReaderError where e.code == .readerSessionInvalidationErrorUserCanceled:
            return "読み取りをキャンセルしました。"
        case let e as Prover.ProverError where e.description == "inputs do not satisfy the circuit":
            return "このカードでは証明を作成できませんでした。"
        case is Prover.ProverError:
            return "証明の作成に失敗しました。"
        default:
            return "カードの読み取りに失敗しました。カードを当て直してください。"
        }
    }
}
