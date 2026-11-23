import CommonCrypto
import CryptoKit
import Foundation

// Reading an ICAO electronic passport (Doc 9303, eighth edition): Basic Access
// Control, secure messaging, transparent files and Active Authentication.
//
// Everything here follows Doc 9303 Parts 3, 10 and 11, and the tests replay the
// worked examples of Part 11 Appendix D byte for byte. The ciphers themselves
// (DES, 3DES, SHA-1) come from the operating system; only the protocol is ours.

public enum PassportError: Error, Equatable {
    /// The document number, date of birth or date of expiry is not well formed.
    case mrzFormat
    /// The chip did not accept the key derived from the MRZ data, or its answer did not check out.
    case accessDenied
    /// A protected response failed its integrity check or was malformed.
    case secureMessaging(String)
    case status(step: String, sw: UInt16)
    case unexpectedData(String)
}

/// The three MRZ fields the access key is derived from (Part 11, 4.3 and Appendix D.2).
public struct MRZKey: Equatable, Sendable {
    /// Document number + check digit + date of birth + check digit + date of expiry + check digit.
    public let information: String

    /// - Parameters:
    ///   - documentNumber: as printed (letters and digits); shorter numbers are padded with `<`
    ///   - dateOfBirth / dateOfExpiry: YYMMDD
    public init(documentNumber: String, dateOfBirth: String, dateOfExpiry: String) throws {
        let number = documentNumber.uppercased().trimmingCharacters(in: .whitespaces)
        let isMRZ = { (s: String) in s.unicodeScalars.allSatisfy { ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "<" } }
        let isDate = { (s: String) in s.count == 6 && s.unicodeScalars.allSatisfy { ("0"..."9").contains($0) } }
        guard (1...9).contains(number.count), isMRZ(number), isDate(dateOfBirth), isDate(dateOfExpiry) else {
            throw PassportError.mrzFormat
        }
        let padded = number + String(repeating: "<", count: 9 - number.count)
        information =
            padded + Self.checkDigit(padded) + dateOfBirth + Self.checkDigit(dateOfBirth) + dateOfExpiry
            + Self.checkDigit(dateOfExpiry)
    }

    /// Part 3, 4.9: weights 7, 3, 1 repeating; digits count as themselves, A-Z as 10-35, `<` as 0; modulus 10.
    static func checkDigit(_ field: String) -> String {
        let weights = [7, 3, 1]
        var sum = 0
        for (i, c) in field.unicodeScalars.enumerated() {
            let value: Int
            switch c {
            case "0"..."9": value = Int(c.value - 48)
            case "A"..."Z": value = Int(c.value - 55)
            default: value = 0
            }
            sum += value * weights[i % 3]
        }
        return String(sum % 10)
    }

    /// K_seed: the first 16 bytes of SHA-1(MRZ information).
    var seed: Data { Data(Insecure.SHA1.hash(data: Data(information.utf8))).prefix(16) }
}

enum PassportCrypto {
    /// Part 11, 9.7.1: a two-key 3DES key from a seed and a counter (1 = encryption, 2 = MAC),
    /// with DES parity bits adjusted.
    static func deriveKey(seed: Data, counter: UInt32) -> Data {
        var input = seed
        withUnsafeBytes(of: counter.bigEndian) { input.append(contentsOf: $0) }
        return Data(Data(Insecure.SHA1.hash(data: input)).prefix(16).map { byte in
            // Odd parity: the low bit makes the number of set bits odd.
            (byte & 0xFE).nonzeroBitCount % 2 == 0 ? (byte & 0xFE) | 1 : byte & 0xFE
        })
    }

    /// ISO/IEC 9797-1 padding method 2: 0x80, then zeros to a multiple of 8.
    static func pad(_ data: Data) -> Data {
        var out = data
        out.append(0x80)
        while out.count % 8 != 0 { out.append(0x00) }
        return out
    }

    static func unpad(_ data: Data) throws -> Data {
        guard let i = data.lastIndex(where: { $0 != 0x00 }), data[i] == 0x80 else {
            throw PassportError.secureMessaging("bad padding")
        }
        return data.prefix(upTo: i)
    }

    private static func crypt(_ operation: Int, algorithm: Int, key: Data, data: Data) -> Data {
        precondition(data.count % 8 == 0)
        var out = Data(count: data.count + 8)
        var moved = 0
        let iv = Data(count: 8)
        let status = out.withUnsafeMutableBytes { o in
            data.withUnsafeBytes { d in
                key.withUnsafeBytes { k in
                    iv.withUnsafeBytes { v in
                        CCCrypt(
                            CCOperation(operation), CCAlgorithm(algorithm), 0, k.baseAddress, key.count,
                            v.baseAddress, d.baseAddress, data.count, o.baseAddress, o.count, &moved)
                    }
                }
            }
        }
        precondition(status == kCCSuccess, "cipher failure")
        return out.prefix(moved)
    }

    /// Two-key 3DES in CBC mode with a zero IV, no padding (Part 11, 4.3.3.1 and 9.8.6.1).
    static func tdes(encrypt: Bool, key: Data, _ data: Data) -> Data {
        // CommonCrypto wants K1 | K2 | K1.
        crypt(encrypt ? kCCEncrypt : kCCDecrypt, algorithm: kCCAlgorithm3DES, key: key + key.prefix(8), data: data)
    }

    /// ISO/IEC 9797-1 MAC algorithm 3 ("retail MAC") with DES, zero IV; `data` already padded.
    static func mac(key: Data, _ data: Data) -> Data {
        let k1 = key.prefix(8)
        let k2 = key.suffix(8)
        // DES-CBC under K1 over everything; the last block is the intermediate value.
        let chained = crypt(kCCEncrypt, algorithm: kCCAlgorithmDES, key: Data(k1), data: data).suffix(8)
        let decrypted = crypt(kCCDecrypt, algorithm: kCCAlgorithmDES, key: Data(k2), data: Data(chained))
        return crypt(kCCEncrypt, algorithm: kCCAlgorithmDES, key: Data(k1), data: decrypted)
    }
}

/// Session keys and counter of secure messaging (Part 11, 9.8).
public final class SecureMessaging {
    let ksEnc: Data
    let ksMac: Data
    private(set) var ssc: Data

    init(ksEnc: Data, ksMac: Data, ssc: Data) {
        self.ksEnc = ksEnc
        self.ksMac = ksMac
        self.ssc = ssc
    }

    private func incrementSSC() {
        var bytes = [UInt8](ssc)
        for i in stride(from: bytes.count - 1, through: 0, by: -1) {
            bytes[i] &+= 1
            if bytes[i] != 0 { break }
        }
        ssc = Data(bytes)
    }

    private static func dataObject(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag])
        switch value.count {
        case 0..<0x80: out.append(UInt8(value.count))
        case 0x80..<0x100: out.append(contentsOf: [0x81, UInt8(value.count)])
        default: out.append(contentsOf: [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)])
        }
        return out + value
    }

    /// Wraps a command: encrypted data in DO'87', expected length in DO'97', checksum in DO'8E'.
    func protect(_ c: CommandAPDU) -> CommandAPDU {
        let header = Data([c.cla | 0x0C, c.ins, c.p1, c.p2])
        var body = Data()
        if !c.data.isEmpty {
            body += Self.dataObject(0x87, Data([0x01]) + PassportCrypto.tdes(encrypt: true, key: ksEnc, PassportCrypto.pad(c.data)))
        }
        if let le = c.le {
            body += Self.dataObject(0x97, Data([UInt8(le & 0xFF)]))
        }
        incrementSSC()
        let checksum = PassportCrypto.mac(key: ksMac, PassportCrypto.pad(ssc + PassportCrypto.pad(header) + body))
        return CommandAPDU(cla: header[0], ins: c.ins, p1: c.p1, p2: c.p2, data: body + Self.dataObject(0x8E, checksum), le: 256)
    }

    /// Checks and unwraps a response. Throws if the checksum does not verify.
    func unprotect(_ r: ResponseAPDU) throws -> ResponseAPDU {
        guard r.isOK else { return r }  // errors come back unprotected
        var rest = r.data
        var covered = Data()
        var encrypted: Data?
        var status: Data?
        var checksum: Data?
        while !rest.isEmpty {
            guard rest.count >= 2 else { throw PassportError.secureMessaging("truncated response") }
            let tag = rest[rest.startIndex]
            var headerLength = 2
            var length = Int(rest[rest.startIndex + 1])
            if length == 0x81, rest.count >= 3 {
                length = Int(rest[rest.startIndex + 2])
                headerLength = 3
            } else if length == 0x82, rest.count >= 4 {
                length = Int(rest[rest.startIndex + 2]) << 8 | Int(rest[rest.startIndex + 3])
                headerLength = 4
            } else if length >= 0x80 {
                throw PassportError.secureMessaging("bad length")
            }
            guard rest.count >= headerLength + length else { throw PassportError.secureMessaging("truncated response") }
            let object = rest.prefix(headerLength + length)
            let value = Data(object.dropFirst(headerLength))
            switch tag {
            case 0x87:
                guard value.first == 0x01 else { throw PassportError.secureMessaging("bad DO87") }
                encrypted = Data(value.dropFirst())
                covered += object
            case 0x99:
                status = value
                covered += object
            case 0x8E:
                checksum = value
            default:
                throw PassportError.secureMessaging("unexpected data object")
            }
            rest = Data(rest.dropFirst(headerLength + length))
        }
        incrementSSC()
        guard let checksum, let status, status.count == 2,
            checksum == PassportCrypto.mac(key: ksMac, PassportCrypto.pad(ssc + covered))
        else { throw PassportError.secureMessaging("checksum mismatch") }

        var plain = Data()
        if let encrypted {
            guard !encrypted.isEmpty, encrypted.count % 8 == 0 else { throw PassportError.secureMessaging("bad ciphertext") }
            plain = try PassportCrypto.unpad(PassportCrypto.tdes(encrypt: false, key: ksEnc, encrypted))
        }
        return ResponseAPDU(data: plain, sw1: status[status.startIndex], sw2: status[status.startIndex + 1])
    }
}

public struct PassportCard<Transport: CardTransport> {
    /// The eMRTD application (Part 10, 3.9.1).
    public static var aid: Data { Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]) }

    /// Elementary files (Part 10, table 38 and 4.6.2).
    public enum File: Sendable {
        case com, sod, dg1, dg14, dg15

        var identifier: [UInt8] {
            switch self {
            case .com: return [0x01, 0x1E]
            case .sod: return [0x01, 0x1D]
            case .dg1: return [0x01, 0x01]
            case .dg14: return [0x01, 0x0E]
            case .dg15: return [0x01, 0x0F]
            }
        }
    }

    /// Bytes requested per READ BINARY. Small enough that the protected response fits a short APDU.
    static var chunk: Int { 0xA0 }
    static var maxFileLength: Int { 32 * 1024 }

    let transport: Transport

    public init(transport: Transport) {
        self.transport = transport
    }

    public func selectApplication() async throws {
        let res = try await transport.transmit(CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: Self.aid))
        guard res.isOK else { throw PassportError.status(step: "SELECT eMRTD application", sw: res.sw) }
    }

    /// Basic Access Control (Part 11, 4.3): mutual authentication with keys derived
    /// from the MRZ, yielding secure messaging keys. A wrong MRZ only fails; the
    /// chip has no retry counter for it.
    ///
    /// `random` supplies RND.IFD (8 bytes) and K.IFD (16 bytes); tests inject the
    /// values of the worked example.
    public func basicAccessControl(mrz: MRZKey, random: (Int) -> Data = PassportCard.systemRandom) async throws -> SecureMessaging {
        let kEnc = PassportCrypto.deriveKey(seed: mrz.seed, counter: 1)
        let kMac = PassportCrypto.deriveKey(seed: mrz.seed, counter: 2)

        let challenge = try await transport.transmit(CommandAPDU(cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, le: 8))
        guard challenge.isOK, challenge.data.count == 8 else {
            throw PassportError.status(step: "GET CHALLENGE", sw: challenge.sw)
        }
        let rndIC = challenge.data
        let rndIFD = random(8)
        let kIFD = random(16)

        let eIFD = PassportCrypto.tdes(encrypt: true, key: kEnc, rndIFD + rndIC + kIFD)
        let mIFD = PassportCrypto.mac(key: kMac, PassportCrypto.pad(eIFD))
        let res = try await transport.transmit(
            CommandAPDU(cla: 0x00, ins: 0x82, p1: 0x00, p2: 0x00, data: eIFD + mIFD, le: 0x28))
        guard res.isOK else { throw PassportError.accessDenied }
        guard res.data.count == 40 else { throw PassportError.accessDenied }

        let eIC = res.data.prefix(32)
        guard PassportCrypto.mac(key: kMac, PassportCrypto.pad(eIC)) == res.data.suffix(8) else {
            throw PassportError.accessDenied
        }
        let r = PassportCrypto.tdes(encrypt: false, key: kEnc, Data(eIC))
        // R = RND.IC | RND.IFD | K.IC: the chip must echo both nonces.
        guard r.prefix(8) == rndIC, r.dropFirst(8).prefix(8) == rndIFD else { throw PassportError.accessDenied }
        let kIC = r.suffix(16)

        let seed = Data(zip(kIFD, kIC).map { $0 ^ $1 })
        return SecureMessaging(
            ksEnc: PassportCrypto.deriveKey(seed: seed, counter: 1),
            ksMac: PassportCrypto.deriveKey(seed: seed, counter: 2),
            ssc: rndIC.suffix(4) + rndIFD.suffix(4))
    }

    public static func systemRandom(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "no randomness")
        return Data(bytes)
    }

    private func exchange(_ command: CommandAPDU, _ sm: SecureMessaging, _ step: String) async throws -> ResponseAPDU {
        let res = try await sm.unprotect(try await transport.transmit(sm.protect(command)))
        guard res.isOK else { throw PassportError.status(step: step, sw: res.sw) }
        return res
    }

    /// Reads a whole transparent file: its first four bytes give the length of the
    /// BER-TLV structure it holds, the rest follows in chunks.
    public func readFile(_ file: File, _ sm: SecureMessaging) async throws -> Data {
        let name = "\(file)"
        _ = try await exchange(
            CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: Data(file.identifier)), sm, "SELECT \(name)")
        let head = try await exchange(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 4), sm, "READ \(name)").data
        guard head.count == 4 else { throw PassportError.unexpectedData("\(name): short header") }

        let total: Int
        switch head[head.startIndex + 1] {
        case let l where l < 0x80: total = 2 + Int(l)
        case 0x81: total = 3 + Int(head[head.startIndex + 2])
        case 0x82: total = 4 + (Int(head[head.startIndex + 2]) << 8 | Int(head[head.startIndex + 3]))
        default: throw PassportError.unexpectedData("\(name): unsupported length")
        }
        guard total >= 4, total <= Self.maxFileLength else { throw PassportError.unexpectedData("\(name): implausible length") }

        var out = head
        while out.count < total {
            let want = min(Self.chunk, total - out.count)
            let part = try await exchange(
                CommandAPDU(cla: 0x00, ins: 0xB0, p1: UInt8(out.count >> 8), p2: UInt8(out.count & 0xFF), le: want),
                sm, "READ \(name)"
            ).data
            guard !part.isEmpty else { throw PassportError.unexpectedData("\(name): file shorter than its header says") }
            out += part.prefix(total - out.count)
        }
        return out
    }

    /// Active Authentication (Part 11, 6.1): the chip signs an 8-byte nonce with a
    /// key that never leaves it. Returns the signature as the chip produced it.
    public func activeAuthentication(nonce: Data, _ sm: SecureMessaging) async throws -> Data {
        precondition(nonce.count == 8, "RND.IFD must be 8 bytes")
        return try await exchange(
            CommandAPDU(cla: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: nonce, le: 256), sm, "INTERNAL AUTHENTICATE"
        ).data
    }
}
