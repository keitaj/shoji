import Foundation
import Testing

@testable import ShojiCardKit

/// The same vector as TestChallengeVector in internal/proto/proto_test.go.
let testChallenge =
    "shoji1:002a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5a:0011111111111111111111111111111111111111111111111111111111111111"

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

struct ChallengeTests {
    @Test func testMatchesTheGoVector() throws {
        let c = try Challenge(testChallenge)
        #expect(c.message.count == 80)
        #expect(String(decoding: c.message.prefix(16), as: UTF8.self) == "shoji-v1-nonce::")
        #expect(hex(c.digest) == "2b1dea3932512903492cb6b7affbda2f97959f6c6f1d9539b3d660aec74ded5a")
        #expect(c.digestInfo.count == 51)
        #expect(hex(c.digestInfo.prefix(19)) == "3031300d060960864801650304020105000420")
        #expect(c.digestInfo.suffix(32) == c.digest)
    }

    @Test func testAcceptsSurroundingWhitespace() throws {
        #expect(try Challenge("  " + testChallenge + "\n") == Challenge(testChallenge))
    }

    @Test func testRejectsAnythingElse() {
        let appID = String(repeating: "0", count: 64)
        let bad = [
            "", "shoji1", "shoji1:\(appID)", "shoji2:\(appID):\(appID)",
            "shoji1:\(appID):\(appID):\(appID)",
            "shoji1:\(appID.dropLast()):\(appID)",  // too short
            "shoji1:\(appID)0:\(appID)",  // too long
            "shoji1:\(String(repeating: "G", count: 64)):\(appID)",  // not hex
            "shoji1:\(String(repeating: "A", count: 64)):\(appID)",  // upper case is not the canonical form
            // A bare digest must never be accepted in place of a challenge.
            "2b1dea3932512903492cb6b7affbda2f97959f6c6f1d9539b3d660aec74ded5a",
        ]
        for text in bad {
            #expect(throws: Challenge.ParseError.malformed) { try Challenge(text) }
        }
    }
}
