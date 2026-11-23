import Foundation

// Commands for the JPKI application of the My Number Card.
//
// The AID, file identifiers and command encodings below are NOT taken from an
// official specification (none is public). They follow two independent
// open-source sources that agree with each other:
//   - jpki/myna (src/jpki.rs, src/reader.rs) at commit 55a90c2
//   - https://tex2e.github.io/blog/protocol/jpki-mynumbercard-with-apdu
// See docs/open-questions.md. Do not add or change a command from memory.

public enum CardError: Error, Equatable {
    /// The card answered a step with an unexpected status word.
    case status(step: String, sw: UInt16)
    /// Data read from the card does not look like what was expected.
    case unexpectedData(String)
    /// The password is not 6-16 characters of A-Z and 0-9. Nothing was sent to the card.
    case passwordFormat
    /// Too few attempts are left; the password was NOT sent to the card.
    case tooFewAttemptsLeft(remaining: Int)
    /// The card rejected the password. One attempt was consumed.
    case wrongPassword(remaining: Int)
}

/// File identifiers inside the JPKI application (see the note on sources above).
enum JPKIFile {
    static let signCertificate: [UInt8] = [0x00, 0x01]
    static let signCACertificate: [UInt8] = [0x00, 0x02]
    static let signPassword: [UInt8] = [0x00, 0x1B]
    static let signKey: [UInt8] = [0x00, 0x1A]
}

public struct JPKICard<Transport: CardTransport> {
    /// JPKI application identifier.
    public static var aid: Data { Data([0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01]) }

    /// The signing password locks after 5 consecutive failures and can only be
    /// unlocked at a municipal office. This code refuses to try unless at least
    /// this many attempts remain, so it can never spend the last ones.
    public static var minimumAttemptsToTry: Int { 3 }

    /// Upper bound for a certificate file; anything larger is treated as a parse error.
    static var maxCertificateLength: Int { 4096 }

    let transport: Transport

    public init(transport: Transport) {
        self.transport = transport
    }

    // MARK: - Steps that need no password

    public func selectApplication() async throws {
        try await expectOK("SELECT JPKI AP", CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: Self.aid))
    }

    /// The signing CA's self-signed certificate (DER). Readable without a password.
    public func readSignCACertificate() async throws -> Data {
        try await selectFile(JPKIFile.signCACertificate, "SELECT sign CA certificate")
        return try await readCertificate("READ sign CA certificate")
    }

    /// Remaining attempts for the signing password. Does not consume an attempt:
    /// VERIFY without data only reports the counter (status 63 Cx).
    public func signPasswordAttemptsLeft() async throws -> Int {
        try await selectFile(JPKIFile.signPassword, "SELECT sign password")
        let res = try await transport.transmit(CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80))
        guard res.sw1 == 0x63 else {
            throw CardError.status(step: "READ sign password counter", sw: res.sw)
        }
        return Int(res.sw2 & 0x0F)
    }

    // MARK: - Steps that need the signing password

    /// Normalises and validates a signing password without touching the card.
    /// Signing passwords are 6-16 characters of upper-case letters and digits.
    public static func normalizedPassword(_ input: String) throws -> Data {
        let upper = input.uppercased()
        let allowed = upper.unicodeScalars.allSatisfy { ("A"..."Z").contains($0) || ("0"..."9").contains($0) }
        guard (6...16).contains(upper.unicodeScalars.count), allowed else {
            throw CardError.passwordFormat
        }
        return Data(upper.utf8)
    }

    /// Reads the signing certificate (DER). It contains the holder's name, address,
    /// date of birth and gender, so the card requires the signing password first.
    ///
    /// Sends the password at most once, and only if at least
    /// `minimumAttemptsToTry` attempts remain.
    public func readSignCertificate(password: String) async throws -> Data {
        try await verifySignPassword(password)
        try await selectFile(JPKIFile.signCertificate, "SELECT sign certificate")
        return try await readCertificate("READ sign certificate")
    }

    /// Has the card sign shoji's nonce message for `challenge` with the signing key
    /// and returns the 256-byte RSA signature (SHA-256, PKCS#1 v1.5).
    ///
    /// The password rules are the same as for `readSignCertificate`. Only a
    /// `Challenge` can be signed, never an arbitrary digest.
    public func sign(_ challenge: Challenge, password: String) async throws -> Data {
        try await verifySignPassword(password)
        try await selectFile(JPKIFile.signKey, "SELECT sign key")
        // COMPUTE DIGITAL SIGNATURE as implemented by jpki/myna: CLA 80, P1/P2 00 80,
        // data = DigestInfo, Le = 00.
        let res = try await transport.transmit(
            CommandAPDU(cla: 0x80, ins: 0x2A, p1: 0x00, p2: 0x80, data: challenge.digestInfo, le: 256))
        guard res.isOK else { throw CardError.status(step: "SIGN", sw: res.sw) }
        guard res.data.count == 256 else {
            throw CardError.unexpectedData("SIGN: signature is not 256 bytes")
        }
        return res.data
    }

    /// Verifies the signing password: at most one attempt, and none at all unless
    /// at least `minimumAttemptsToTry` attempts remain.
    private func verifySignPassword(_ password: String) async throws {
        let pin = try Self.normalizedPassword(password)

        let remaining = try await signPasswordAttemptsLeft()
        guard remaining >= Self.minimumAttemptsToTry else {
            throw CardError.tooFewAttemptsLeft(remaining: remaining)
        }

        // The sign password file is still selected from the counter read above.
        let res = try await transport.transmit(CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80, data: pin))
        if res.sw1 == 0x63 {
            throw CardError.wrongPassword(remaining: Int(res.sw2 & 0x0F))
        }
        guard res.isOK else {
            throw CardError.status(step: "VERIFY sign password", sw: res.sw)
        }
    }

    // MARK: - Helpers

    private func expectOK(_ step: String, _ command: CommandAPDU) async throws {
        let res = try await transport.transmit(command)
        guard res.isOK else { throw CardError.status(step: step, sw: res.sw) }
    }

    private func selectFile(_ fid: [UInt8], _ step: String) async throws {
        try await expectOK(step, CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: Data(fid)))
    }

    /// Reads the currently selected file, which must hold one DER SEQUENCE with a
    /// two-byte length (30 82 hh ll ...), as every RSA-2048 certificate does.
    private func readCertificate(_ step: String) async throws -> Data {
        let head = try await readBinary(offset: 0, count: 4, step)
        guard head.count == 4, head[head.startIndex] == 0x30, head[head.startIndex + 1] == 0x82 else {
            throw CardError.unexpectedData("\(step): file does not start with a DER certificate header")
        }
        let bodyLength = Int(head[head.startIndex + 2]) << 8 | Int(head[head.startIndex + 3])
        guard bodyLength > 0, 4 + bodyLength <= Self.maxCertificateLength else {
            throw CardError.unexpectedData("\(step): implausible certificate length")
        }
        let body = try await readBinary(offset: 4, count: bodyLength, step)
        guard body.count == bodyLength else {
            throw CardError.unexpectedData("\(step): file shorter than its header says")
        }
        return head + body
    }

    /// READ BINARY in chunks, the same way jpki/myna does: Le = 0x00 (256 bytes)
    /// while more than 255 bytes remain, otherwise the exact remainder.
    private func readBinary(offset: Int, count: Int, _ step: String) async throws -> Data {
        var out = Data()
        var pos = offset
        let end = offset + count
        while pos < end {
            let remaining = end - pos
            let le = remaining > 0xFF ? 256 : remaining
            let res = try await transport.transmit(
                CommandAPDU(cla: 0x00, ins: 0xB0, p1: UInt8(pos >> 8), p2: UInt8(pos & 0xFF), le: le))
            guard res.isOK else { throw CardError.status(step: step, sw: res.sw) }
            if res.data.isEmpty { break }
            out.append(res.data.prefix(remaining))
            pos += res.data.count
        }
        return out
    }
}
