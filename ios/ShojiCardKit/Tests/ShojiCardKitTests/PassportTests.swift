import Foundation
import Testing

@testable import ShojiCardKit

func bytes(_ hexString: String) -> Data {
    var out = Data()
    var s = Substring(hexString.filter { !$0.isWhitespace })
    while !s.isEmpty {
        out.append(UInt8(s.prefix(2), radix: 16)!)
        s = s.dropFirst(2)
    }
    return out
}

/// Replays a fixed sequence of exchanges and fails on anything else.
final class ScriptedCard: CardTransport {
    private var script: [(command: Data, response: Data)]
    private(set) var mismatches: [String] = []

    init(_ script: [(String, String)]) {
        self.script = script.map { (bytes($0.0), bytes($0.1)) }
    }

    var isExhausted: Bool { script.isEmpty }

    func transmit(_ c: CommandAPDU) async throws -> ResponseAPDU {
        guard !script.isEmpty else {
            mismatches.append("unexpected command \(hex(c.bytes))")
            return ResponseAPDU(sw1: 0x6F, sw2: 0x00)
        }
        let (expected, response) = script.removeFirst()
        if c.bytes != expected { mismatches.append("sent \(hex(c.bytes)), expected \(hex(expected))") }
        return ResponseAPDU(data: response.dropLast(2), sw1: response[response.count - 2], sw2: response[response.count - 1])
    }
}

/// The worked examples of ICAO Doc 9303 Part 11 (eighth edition), Appendix D.
struct PassportTests {
    // D.3: the terminal's random values.
    static let rndIFD = bytes("781723860C06C226")
    static let kIFD = bytes("0B795240CB7049B01C19B33E32804F0B")
    static func fixedRandom(_ n: Int) -> Data { n == 8 ? rndIFD : kIFD }

    static let bacExchange: [(String, String)] = [
        ("0084000008", "4608F91988702212 9000"),
        (
            "0082000028 72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7 28",
            "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449 9000"
        ),
    ]
    // D.4: select EF.COM, read 4 bytes, read the remaining 18.
    static let readCOM: [(String, String)] = [
        ("0CA4020C15 8709016375432908C044F6 8E08BF8B92D635FF24F8 00", "990290008E08FA855A5D4C50A8ED 9000"),
        ("0CB000000D 970104 8E08ED6705417E96BA55 00", "8709019FF0EC34F992265199029000 8E08AD55CC17140B2DED 9000"),
        (
            "0CB000040D 970112 8E082EA28A70F3C7B535 00",
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000 8E08C8B2787EAEA07D74 9000"
        ),
    ]

    func mrz() throws -> MRZKey {
        try MRZKey(documentNumber: "L898902C", dateOfBirth: "690806", dateOfExpiry: "940623")
    }

    @Test func testKeyDerivationD1() {
        let seed = bytes("239AB9CB282DAF66231DC5A4DF6BFBAE")
        #expect(PassportCrypto.deriveKey(seed: seed, counter: 1) == bytes("AB94FDECF2674FDFB9B391F85D7F76F2"))
        #expect(PassportCrypto.deriveKey(seed: seed, counter: 2) == bytes("7962D9ECE03D1ACD4C76089DCE131543"))
    }

    @Test func testMRZInformationD2() throws {
        #expect(try mrz().information == "L898902C<369080619406236")
        #expect(try mrz().seed == bytes("239AB9CB282DAF66231DC5A4DF6BFBAE"))
        // Check digits for a document number that fills all nine characters, from the same appendix.
        #expect(MRZKey.checkDigit("340712") == "7")
        #expect(MRZKey.checkDigit("950712") == "2")
    }

    @Test func testRejectsMalformedMRZFields() {
        #expect(throws: PassportError.mrzFormat) { try MRZKey(documentNumber: "", dateOfBirth: "690806", dateOfExpiry: "940623") }
        #expect(throws: PassportError.mrzFormat) { try MRZKey(documentNumber: "L898902C12", dateOfBirth: "690806", dateOfExpiry: "940623") }
        #expect(throws: PassportError.mrzFormat) { try MRZKey(documentNumber: "L8989-2C", dateOfBirth: "690806", dateOfExpiry: "940623") }
        #expect(throws: PassportError.mrzFormat) { try MRZKey(documentNumber: "L898902C", dateOfBirth: "19690806", dateOfExpiry: "940623") }
        #expect(throws: PassportError.mrzFormat) { try MRZKey(documentNumber: "L898902C", dateOfBirth: "690806", dateOfExpiry: "94O623") }
    }

    @Test func testBasicAccessControlD3() async throws {
        let card = ScriptedCard(Self.bacExchange)
        let sm = try await PassportCard(transport: card).basicAccessControl(mrz: mrz(), random: Self.fixedRandom)
        #expect(card.mismatches.isEmpty, "\(card.mismatches)")
        #expect(card.isExhausted)
        #expect(sm.ksEnc == bytes("979EC13B1CBFE9DCD01AB0FED307EAE5"))
        #expect(sm.ksMac == bytes("F1CB1F1FB5ADF208806B89DC579DC1F8"))
        #expect(sm.ssc == bytes("887022120C06C226"))
    }

    @Test func testSecureMessagingReadD4() async throws {
        let card = ScriptedCard(Self.bacExchange + Self.readCOM)
        let passport = PassportCard(transport: card)
        let sm = try await passport.basicAccessControl(mrz: mrz(), random: Self.fixedRandom)
        let com = try await passport.readFile(.com, sm)
        #expect(card.mismatches.isEmpty, "\(card.mismatches)")
        #expect(card.isExhausted)
        #expect(com == bytes("60145F0104303130365F36063034303030305C026175"))
    }

    @Test func testWrongMRZIsRefused() async throws {
        // The chip answers EXTERNAL AUTHENTICATE with an error when the keys do not match.
        let card = ScriptedCard([("0084000008", "4608F91988702212 9000")])
        let wrong = try MRZKey(documentNumber: "L898902D", dateOfBirth: "690806", dateOfExpiry: "940623")
        await #expect(throws: PassportError.accessDenied) {
            _ = try await PassportCard(transport: card).basicAccessControl(mrz: wrong, random: Self.fixedRandom)
        }
    }

    @Test func testChipAnswerThatDoesNotEchoTheNonceIsRefused() async throws {
        // Same chip answer, but the terminal used another RND.IFD: the echo check must fail.
        let card = ScriptedCard([
            Self.bacExchange[0],
            ("", Self.bacExchange[1].1),
        ])
        await #expect(throws: PassportError.accessDenied) {
            _ = try await PassportCard(transport: card).basicAccessControl(mrz: mrz()) { n in
                n == 8 ? bytes("0000000000000000") : Self.kIFD
            }
        }
    }

    @Test func testTamperedResponseFailsTheChecksum() async throws {
        var tampered = Self.readCOM
        // Flip one bit of the encrypted data in the second response.
        tampered[1].1 = "8709019FF0EC34F992265099029000 8E08AD55CC17140B2DED 9000"
        let card = ScriptedCard(Self.bacExchange + tampered)
        let passport = PassportCard(transport: card)
        let sm = try await passport.basicAccessControl(mrz: mrz(), random: Self.fixedRandom)
        await #expect(throws: PassportError.secureMessaging("checksum mismatch")) {
            _ = try await passport.readFile(.com, sm)
        }
    }
}
