import Foundation
import Testing

@testable import ShojiCardKit

/// A minimal in-memory card: files, one password with a retry counter, and a
/// log of every command it received.
final class FakeCard: CardTransport {
    var files: [[UInt8]: Data] = [:]
    var password = Data("ABC123".utf8)
    var attemptsLeft = 5
    var verified = false
    var selected: [UInt8]?
    var applicationSelected = false
    private(set) var log: [CommandAPDU] = []
    private(set) var signedData: [Data] = []

    var verifyCommandsWithData: Int { log.filter { $0.ins == 0x20 && !$0.data.isEmpty }.count }

    func transmit(_ c: CommandAPDU) async throws -> ResponseAPDU {
        log.append(c)
        switch (c.ins, c.p1) {
        case (0xA4, 0x04):
            applicationSelected = c.data == JPKICard<FakeCard>.aid
            return ResponseAPDU(sw1: applicationSelected ? 0x90 : 0x6A, sw2: applicationSelected ? 0x00 : 0x82)
        case (0xA4, 0x02):
            guard applicationSelected else { return ResponseAPDU(sw1: 0x6A, sw2: 0x82) }
            selected = [UInt8](c.data)
            return ResponseAPDU(sw1: 0x90, sw2: 0x00)
        case (0x20, _):
            guard selected == [0x00, 0x1B] else { return ResponseAPDU(sw1: 0x6A, sw2: 0x86) }
            if c.data.isEmpty { return ResponseAPDU(sw1: 0x63, sw2: 0xC0 | UInt8(attemptsLeft)) }
            guard attemptsLeft > 0 else { return ResponseAPDU(sw1: 0x69, sw2: 0x84) }
            if c.data == password {
                verified = true
                attemptsLeft = 5
                return ResponseAPDU(sw1: 0x90, sw2: 0x00)
            }
            attemptsLeft -= 1
            return ResponseAPDU(sw1: 0x63, sw2: 0xC0 | UInt8(attemptsLeft))
        case (0xB0, _):
            guard let fid = selected, let file = files[fid] else { return ResponseAPDU(sw1: 0x6A, sw2: 0x82) }
            if fid == [0x00, 0x01] && !verified { return ResponseAPDU(sw1: 0x69, sw2: 0x82) }
            let off = Int(c.p1) << 8 | Int(c.p2)
            guard off <= file.count else { return ResponseAPDU(sw1: 0x6B, sw2: 0x00) }
            return ResponseAPDU(data: file.subdata(in: off..<min(file.count, off + (c.le ?? 0))), sw1: 0x90, sw2: 0x00)
        case (0x2A, _):
            // COMPUTE DIGITAL SIGNATURE: only with the key selected and the password verified.
            guard selected == [0x00, 0x1A], verified else { return ResponseAPDU(sw1: 0x69, sw2: 0x82) }
            guard c.cla == 0x80, c.p1 == 0x00, c.p2 == 0x80, c.le == 256 else { return ResponseAPDU(sw1: 0x6A, sw2: 0x86) }
            signedData.append(c.data)
            return ResponseAPDU(data: Data(repeating: 0x5A, count: 256), sw1: 0x90, sw2: 0x00)
        default:
            return ResponseAPDU(sw1: 0x6D, sw2: 0x00)
        }
    }
}

func fakeCertificate(bodyLength: Int, fill: UInt8) -> Data {
    Data([0x30, 0x82, UInt8(bodyLength >> 8), UInt8(bodyLength & 0xFF)]) + Data(repeating: fill, count: bodyLength)
}

struct JPKICardTests {
    func makeCard() -> FakeCard {
        let card = FakeCard()
        card.files[[0x00, 0x01]] = fakeCertificate(bodyLength: 1738, fill: 0xAA) + Data(repeating: 0xFF, count: 40)
        card.files[[0x00, 0x02]] = fakeCertificate(bodyLength: 900, fill: 0xBB)
        return card
    }

    @Test func testCommandEncodingsMatchTheSources() {
        // SELECT DF, as in jpki/myna and tex2e's write-up.
        #expect([UInt8](CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: JPKICard<FakeCard>.aid).bytes) == [0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01])
        // SELECT EF 00 1B.
        #expect([UInt8](CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: Data([0x00, 0x1B])).bytes) == [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B])
        // VERIFY "123456".
        #expect([UInt8](CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80, data: Data("123456".utf8)).bytes) == [0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        // Counter read: header only. READ BINARY of 256 bytes: Le = 00.
        #expect([UInt8](CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80).bytes) == [0x00, 0x20, 0x00, 0x80])
        #expect([UInt8](CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x01, p2: 0x04, le: 256).bytes) == [0x00, 0xB0, 0x01, 0x04, 0x00])
    }

    @Test func testReadsCACertificateAndCounterWithoutPassword() async throws {
        let card = makeCard()
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        let ca = try await jpki.readSignCACertificate()
        #expect(ca == card.files[[0x00, 0x02]])
        let left = try await jpki.signPasswordAttemptsLeft()
        #expect(left == 5)
        #expect(card.verifyCommandsWithData == 0)
        #expect(card.attemptsLeft == 5)
    }

    @Test func testReadsSignCertificateExactlyToItsDERLength() async throws {
        let card = makeCard()
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        let cert = try await jpki.readSignCertificate(password: "abc123")  // lower case is normalised
        #expect(cert == fakeCertificate(bodyLength: 1738, fill: 0xAA))  // trailing file padding not included
        #expect(card.verifyCommandsWithData == 1)
    }

    @Test func testWrongPasswordIsSentOnceAndReported() async throws {
        let card = makeCard()
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        do {
            _ = try await jpki.readSignCertificate(password: "WRONG99")
            Issue.record("expected an error")
        } catch let e as CardError {
            #expect(e == .wrongPassword(remaining: 4))
        }
        #expect(card.verifyCommandsWithData == 1)
        #expect(card.attemptsLeft == 4)
    }

    @Test func testRefusesToTryWhenFewAttemptsRemain() async throws {
        for left in [0, 1, 2] {
            let card = makeCard()
            card.attemptsLeft = left
            let jpki = JPKICard(transport: card)
            try await jpki.selectApplication()
            do {
                _ = try await jpki.readSignCertificate(password: "ABC123")  // even the correct one
                Issue.record("expected an error")
            } catch let e as CardError {
                #expect(e == .tooFewAttemptsLeft(remaining: left))
            }
            #expect(card.verifyCommandsWithData == 0, "the password must not reach the card")
            #expect(card.attemptsLeft == left)
        }
    }

    @Test func testMalformedPasswordNeverReachesTheCard() async throws {
        for bad in ["", "12345", "1234", "ABC 123", "ABC-123", "あいうえおか", String(repeating: "A", count: 17)] {
            let card = makeCard()
            let jpki = JPKICard(transport: card)
            try await jpki.selectApplication()
            let before = card.log.count
            do {
                _ = try await jpki.readSignCertificate(password: bad)
                Issue.record("expected an error for \(bad)")
            } catch let e as CardError {
                #expect(e == .passwordFormat)
            }
            #expect(card.log.count == before, "nothing may be sent for a malformed password")
        }
    }

    @Test func testSignsOnlyTheChallengeMessage() async throws {
        let card = makeCard()
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        let challenge = try Challenge(testChallenge)
        let signature = try await jpki.sign(challenge, password: "ABC123")
        #expect(signature.count == 256)
        #expect(card.signedData == [challenge.digestInfo])
        #expect(card.verifyCommandsWithData == 1)
    }

    @Test func testReadsCertificateAndSignsWithOnePasswordVerification() async throws {
        let card = makeCard()
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        let challenge = try Challenge(testChallenge)
        let (certificate, signature) = try await jpki.readSignCertificateAndSign(challenge, password: "ABC123")
        #expect(certificate == fakeCertificate(bodyLength: 1738, fill: 0xAA))
        #expect(signature.count == 256)
        #expect(card.signedData == [challenge.digestInfo])
        #expect(card.verifyCommandsWithData == 1)
    }

    @Test func testDoesNotSignWithWrongPasswordOrFewAttempts() async throws {
        let challenge = try Challenge(testChallenge)

        let wrong = makeCard()
        try await JPKICard(transport: wrong).selectApplication()
        do {
            _ = try await JPKICard(transport: wrong).sign(challenge, password: "WRONG99")
            Issue.record("expected an error")
        } catch let e as CardError {
            #expect(e == .wrongPassword(remaining: 4))
        }
        #expect(wrong.signedData.isEmpty)

        let low = makeCard()
        low.attemptsLeft = 2
        try await JPKICard(transport: low).selectApplication()
        do {
            _ = try await JPKICard(transport: low).sign(challenge, password: "ABC123")
            Issue.record("expected an error")
        } catch let e as CardError {
            #expect(e == .tooFewAttemptsLeft(remaining: 2))
        }
        #expect(low.signedData.isEmpty)
        #expect(low.verifyCommandsWithData == 0)
    }

    @Test func testRejectsFileThatIsNotACertificate() async throws {
        let card = makeCard()
        card.files[[0x00, 0x02]] = Data(repeating: 0xFF, count: 64)
        let jpki = JPKICard(transport: card)
        try await jpki.selectApplication()
        do {
            _ = try await jpki.readSignCACertificate()
            Issue.record("expected an error")
        } catch let e as CardError {
            guard case .unexpectedData = e else { Issue.record("unexpected error \(e)"); return }
        }
    }
}
