import CoreNFC
import Foundation
import ShojiCardKit

/// Carries APDUs to the card over CoreNFC.
struct NFCTransport: CardTransport {
    let tag: NFCISO7816Tag

    func transmit(_ command: CommandAPDU) async throws -> ResponseAPDU {
        let apdu = NFCISO7816APDU(
            instructionClass: command.cla,
            instructionCode: command.ins,
            p1Parameter: command.p1,
            p2Parameter: command.p2,
            data: command.data,
            expectedResponseLength: command.le ?? -1)
        let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }
}

enum SessionError: Error {
    case nfcUnavailable
    case notACard
}

/// One NFC session = one tap of the card = one job.
final class NFCCardSession: NSObject, NFCTagReaderSessionDelegate {
    enum Job {
        /// Reads the signing CA certificate and the password retry counter. Sends no password.
        case withoutPassword
        /// Additionally verifies the signing password (once) and reads the signing certificate.
        case signCertificate(password: String)
    }

    struct Output {
        var caCertificate: Data?
        var attemptsLeft: Int?
        var signCertificate: Data?
    }

    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<Output, Error>?
    private var job: Job = .withoutPassword

    func run(_ job: Job) async throws -> Output {
        guard NFCTagReaderSession.readingAvailable else { throw SessionError.nfcUnavailable }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            self.job = job
            let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: .main)
            session?.alertMessage = "マイナンバーカードを iPhone の上部に当ててください"
            self.session = session
            session?.begin()
        }
    }

    /// Resumes the caller exactly once; later calls (e.g. the invalidation
    /// callback that follows a normal finish) are ignored.
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
        guard tags.count == 1, case .iso7816(let tag) = tags[0] else {
            finish(.failure(SessionError.notACard))
            session.invalidate(errorMessage: "カードを1枚だけ当ててください")
            return
        }
        let job = self.job
        Task { @MainActor in
            do {
                try await session.connect(to: tags[0])
                let card = JPKICard(transport: NFCTransport(tag: tag))
                var out = Output()

                try await card.selectApplication()
                out.caCertificate = try await card.readSignCACertificate()
                out.attemptsLeft = try await card.signPasswordAttemptsLeft()
                if case .signCertificate(let password) = job {
                    // readSignCertificate re-checks the counter and sends the password at most once.
                    out.signCertificate = try await card.readSignCertificate(password: password)
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
