import CryptoKit
import Foundation

/// A request to verify, as carried by a service's QR code:
/// `shoji://verify?u=<origin>&s=<session>`.
///
/// The origin is the only thing identifying the service. The phone talks to that
/// origin and derives `app_id` from it, so a proof made for one service is
/// useless to any other, whatever a server claims.
public struct VerificationLink: Equatable, Sendable {
    /// `scheme://host[:port]`, lower case, exactly as the verifier spells it.
    public let origin: String
    /// The verification session, 32 hex digits.
    public let session: String

    public enum ParseError: Error, Equatable {
        case malformed
        /// Plain http is accepted only for addresses on the local network (development).
        case insecureOrigin
    }

    public init(_ url: URL) throws {
        guard url.scheme == "shoji", url.host == "verify",
            let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
            items.count == 2,
            let origin = items.first(where: { $0.name == "u" })?.value,
            let session = items.first(where: { $0.name == "s" })?.value
        else { throw ParseError.malformed }

        guard session.utf8.count == 32, session.utf8.allSatisfy({ Self.isLowerHex($0) }) else {
            throw ParseError.malformed
        }
        // The origin must have exactly one spelling: scheme://host[:port], lower case.
        guard let parts = URLComponents(string: origin), let scheme = parts.scheme, let host = parts.host,
            !host.isEmpty, parts.path.isEmpty, parts.query == nil, parts.fragment == nil,
            parts.user == nil, parts.password == nil,
            origin == origin.lowercased(),
            origin == scheme + "://" + host + (parts.port.map { ":\($0)" } ?? "")
        else { throw ParseError.malformed }

        switch scheme {
        case "https":
            break
        case "http":
            guard Self.isLocalNetworkHost(host) else { throw ParseError.insecureOrigin }
        default:
            throw ParseError.malformed
        }
        self.origin = origin
        self.session = session
    }

    /// The host shown to the user as "who is asking".
    public var host: String { URLComponents(string: origin)?.host ?? origin }

    /// True when the connection is not protected by TLS (local development only).
    public var isInsecure: Bool { origin.hasPrefix("http://") }

    /// `app_id` of this origin: the first 31 bytes of SHA-256(origin) as a 32-byte
    /// big-endian field element. Same as `proto.AppID` on the server.
    public var appID: Data {
        Data([0]) + Data(SHA256.hash(data: Data(origin.utf8))).prefix(31)
    }

    private static func isLowerHex(_ c: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(c)
    }

    /// Private IPv4 ranges, loopback and `.local` names.
    static func isLocalNetworkHost(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") { return true }
        let octets = host.split(separator: ".", omittingEmptySubsequences: false).map { UInt8($0) }
        guard octets.count == 4, !octets.contains(nil) else { return false }
        let o = octets.map { $0! }
        return o[0] == 10 || o[0] == 127 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16...31).contains(o[1]))
    }
}

/// What the verifier sends for a session, and the checks the phone applies
/// before the card is involved.
public struct VerificationRequest: Equatable, Sendable {
    public let challenge: Challenge
    public let currentDate: Int
    public let ageThreshold: Int
    public let caPubkeyHash: String

    public enum CheckError: Error, Equatable {
        case malformed
        /// The server asked for a proof for some other service's app_id.
        case wrongApplication
        /// The server's date is not today. Choosing the date would let a server
        /// probe the holder's birthday one comparison at a time.
        case wrongDate
        case unsupportedThreshold
        /// More than one trusted CA key: choosing between them is not implemented.
        case ambiguousCA
    }

    /// - Parameters:
    ///   - appID / nonce: field elements as "0x" + 64 hex digits, from the server
    ///   - today: the phone's own date as YYYYMMDD in Japan Standard Time
    public init(
        link: VerificationLink, appID: String, nonce: String, currentDate: Int, ageThreshold: Int,
        trustedCAHashes: [String], today: Int
    ) throws {
        func strip(_ s: String) -> String { s.hasPrefix("0x") ? String(s.dropFirst(2)) : s }
        guard let challenge = try? Challenge("\(Challenge.prefix):\(strip(appID)):\(strip(nonce))") else {
            throw CheckError.malformed
        }
        guard challenge.appID == link.appID else { throw CheckError.wrongApplication }
        // Allow one day either way for time zones and clocks around midnight.
        guard let diff = Self.dayDifference(currentDate, today), abs(diff) <= 1 else { throw CheckError.wrongDate }
        guard (1...120).contains(ageThreshold) else { throw CheckError.unsupportedThreshold }
        guard trustedCAHashes.count == 1, let hash = trustedCAHashes.first else { throw CheckError.ambiguousCA }
        self.challenge = challenge
        self.currentDate = currentDate
        self.ageThreshold = ageThreshold
        self.caPubkeyHash = hash
    }

    /// The request in the form the prover takes.
    public func proverRequestJSON() throws -> Data {
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        return try JSONSerialization.data(withJSONObject: [
            "challenge": "\(Challenge.prefix):\(hex(challenge.appID)):\(hex(challenge.nonce))",
            "current_date": currentDate,
            "age_threshold": ageThreshold,
            "ca_pubkey_hash": caPubkeyHash,
        ] as [String: Any])
    }

    /// Today's date in Japan Standard Time as YYYYMMDD.
    public static func todayInJapan(_ now: Date = Date()) -> Int {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Asia/Tokyo") ?? TimeZone(secondsFromGMT: 9 * 3600)!
        let c = calendar.dateComponents([.year, .month, .day], from: now)
        return (c.year ?? 0) * 10000 + (c.month ?? 0) * 100 + (c.day ?? 0)
    }

    /// Days from `b` to `a`, both YYYYMMDD; nil if either is not a real date.
    static func dayDifference(_ a: Int, _ b: Int) -> Int? {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        func date(_ v: Int) -> Date? {
            let c = DateComponents(year: v / 10000, month: v / 100 % 100, day: v % 100)
            guard c.isValidDate(in: calendar) else { return nil }
            return calendar.date(from: c)
        }
        guard let da = date(a), let db = date(b) else { return nil }
        return calendar.dateComponents([.day], from: db, to: da).day
    }
}
