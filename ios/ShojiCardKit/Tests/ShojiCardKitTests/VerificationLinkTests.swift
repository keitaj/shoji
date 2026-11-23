import Foundation
import Testing

@testable import ShojiCardKit

struct VerificationLinkTests {
    let session = "0123456789abcdef0123456789abcdef"

    func link(_ origin: String) throws -> VerificationLink {
        var c = URLComponents()
        c.scheme = "shoji"
        c.host = "verify"
        c.queryItems = [URLQueryItem(name: "u", value: origin), URLQueryItem(name: "s", value: session)]
        return try VerificationLink(c.url!)
    }

    @Test func testParsesTheLinkTheVerifierProduces() throws {
        // Exactly the string SessionLink() builds on the Go side.
        let l = try VerificationLink(URL(string: "shoji://verify?u=https%3A%2F%2Fverifier.example&s=\(session)")!)
        #expect(l.origin == "https://verifier.example")
        #expect(l.session == session)
        #expect(l.host == "verifier.example")
        #expect(!l.isInsecure)
    }

    @Test func testAppIDMatchesTheGoVector() throws {
        // TestAppIDOfOriginVector in internal/proto/proto_test.go.
        #expect(hex(try link("https://verifier.example").appID) == "00d1b8790504951c2f3c74c61299b9cfb8634ca1b0dc8e3b6ae57475bc37790a")
        // A different origin is a different application.
        #expect(try link("https://verifier.example").appID != link("https://verifier.example:8443").appID)
    }

    @Test func testPlainHTTPOnlyOnTheLocalNetwork() throws {
        for ok in ["http://192.168.1.20:8080", "http://10.0.0.5:8080", "http://172.16.3.4", "http://127.0.0.1:8080", "http://mac.local:8080"] {
            #expect(try link(ok).isInsecure)
        }
        for bad in ["http://verifier.example", "http://8.8.8.8", "http://172.32.0.1", "http://192.169.1.1", "http://example.local.evil.com"] {
            #expect(throws: VerificationLink.ParseError.insecureOrigin) { try link(bad) }
        }
    }

    @Test func testRejectsOriginsWithMoreThanOneSpelling() {
        for bad in [
            "https://verifier.example/", "https://verifier.example/path", "https://Verifier.example",
            "https://user@verifier.example", "https://verifier.example?x=1", "verifier.example", "ftp://verifier.example", "",
        ] {
            #expect(throws: VerificationLink.ParseError.malformed) { try link(bad) }
        }
    }

    @Test func testRejectsOtherLinks() {
        for bad in [
            "https://verify?u=https%3A%2F%2Fverifier.example&s=\(session)",
            "shoji://other?u=https%3A%2F%2Fverifier.example&s=\(session)",
            "shoji://verify?u=https%3A%2F%2Fverifier.example",
            "shoji://verify?u=https%3A%2F%2Fverifier.example&s=1234",
            "shoji://verify?u=https%3A%2F%2Fverifier.example&s=\(session.uppercased())",
            "shoji://verify?u=https%3A%2F%2Fverifier.example&s=\(session)&x=1",
        ] {
            #expect(throws: VerificationLink.ParseError.malformed) { try VerificationLink(URL(string: bad)!) }
        }
    }
}

struct VerificationRequestTests {
    let nonce = "0x00" + String(repeating: "11", count: 31)
    let today = 20261123

    func link() throws -> VerificationLink {
        try VerificationLink(URL(string: "shoji://verify?u=https%3A%2F%2Fverifier.example&s=0123456789abcdef0123456789abcdef")!)
    }

    func request(appID: String? = nil, date: Int = 20261123, threshold: Int = 18, hashes: [String] = ["0x01"]) throws
        -> VerificationRequest
    {
        let l = try link()
        return try VerificationRequest(
            link: l, appID: appID ?? "0x" + hex(l.appID), nonce: nonce, currentDate: date, ageThreshold: threshold,
            trustedCAHashes: hashes, today: today)
    }

    @Test func testAcceptsAnHonestRequest() throws {
        let r = try request()
        #expect(r.challenge.appID == (try link()).appID)
        let json = try JSONSerialization.jsonObject(with: r.proverRequestJSON()) as! [String: Any]
        #expect(json["current_date"] as? Int == 20261123)
        #expect(json["age_threshold"] as? Int == 18)
        #expect((json["challenge"] as? String)?.hasPrefix("shoji1:00d1b879") == true)
    }

    @Test func testRefusesAnotherServicesAppID() {
        // A server asking for a proof that would be valid at a different service.
        let other = "0x" + String(repeating: "0", count: 62) + "aa"
        #expect(throws: VerificationRequest.CheckError.wrongApplication) { try request(appID: other) }
    }

    @Test func testRefusesDatesThatAreNotToday() throws {
        _ = try request(date: 20261122)
        _ = try request(date: 20261124)
        for bad in [20261121, 20261125, 20500101, 20081123, 20261199, 0] {
            #expect(throws: VerificationRequest.CheckError.wrongDate) { try request(date: bad) }
        }
    }

    @Test func testRefusesOddThresholdsAndAmbiguousCAs() {
        #expect(throws: VerificationRequest.CheckError.unsupportedThreshold) { try request(threshold: 0) }
        #expect(throws: VerificationRequest.CheckError.unsupportedThreshold) { try request(threshold: 200) }
        #expect(throws: VerificationRequest.CheckError.ambiguousCA) { try request(hashes: []) }
        #expect(throws: VerificationRequest.CheckError.ambiguousCA) { try request(hashes: ["0x01", "0x02"]) }
    }

    @Test func testDateHelpers() {
        #expect(VerificationRequest.dayDifference(20270101, 20261231) == 1)
        #expect(VerificationRequest.dayDifference(20260301, 20260228) == 1)
        #expect(VerificationRequest.dayDifference(20260230, 20260228) == nil)
        // 2026-11-22 15:30 UTC is already 2026-11-23 in Japan; an hour earlier it is still the 22nd.
        #expect(VerificationRequest.todayInJapan(Date(timeIntervalSince1970: 1795361400)) == 20261123)
        #expect(VerificationRequest.todayInJapan(Date(timeIntervalSince1970: 1795357800)) == 20261122)
    }
}
