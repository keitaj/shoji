import CryptoKit
import Foundation

/// A verifier challenge in the text form printed by `cardclient challenge`:
/// `shoji1:<app_id>:<nonce>`, each 32 bytes as 64 hex digits.
///
/// The card's signing key makes legally meaningful signatures, so this code never
/// signs a digest handed in from outside. It accepts only a challenge, rebuilds
/// shoji's own message from it (the same bytes as `proto.NonceMessage` in Go and
/// `NONCE_DOMAIN || app_id || nonce` in the circuit) and signs that.
public struct Challenge: Equatable, Sendable {
    public static let prefix = "shoji1"
    static let domain = Data("shoji-v1-nonce::".utf8)

    public let appID: Data  // 32 bytes, big-endian field element
    public let nonce: Data  // 32 bytes, big-endian field element

    public enum ParseError: Error, Equatable {
        case malformed
    }

    public init(_ text: String) throws {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == Substring(Self.prefix),
            let appID = Self.hex32(parts[1]), let nonce = Self.hex32(parts[2])
        else {
            throw ParseError.malformed
        }
        self.appID = appID
        self.nonce = nonce
    }

    private static func hex32(_ s: Substring) -> Data? {
        guard s.utf8.count == 64 else { return nil }
        var out = Data(capacity: 32)
        var high: UInt8?
        for c in s.utf8 {
            let v: UInt8
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): v = c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): v = c - UInt8(ascii: "a") + 10
            default: return nil
            }
            if let h = high {
                out.append(h << 4 | v)
                high = nil
            } else {
                high = v
            }
        }
        return out
    }

    /// The exact 80 bytes that are signed.
    public var message: Data { Self.domain + appID + nonce }

    /// SHA-256 of `message`.
    public var digest: Data { Data(SHA256.hash(data: message)) }

    /// DER DigestInfo for SHA-256 (RFC 8017, section 9.2), which is what the card
    /// pads and signs.
    public var digestInfo: Data {
        Data([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])
            + digest
    }
}
