import Foundation

/// An ISO 7816-4 command with short length fields.
public struct CommandAPDU: Equatable, Sendable {
    public var cla: UInt8
    public var ins: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: Data
    /// Expected response length: nil = no Le field, 1...256 otherwise (256 is encoded as 0x00).
    public var le: Int?

    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data = Data(), le: Int? = nil) {
        precondition(data.count <= 255, "short APDUs only")
        precondition(le == nil || (1...256).contains(le!), "Le out of range")
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le
    }

    /// Wire encoding.
    public var bytes: Data {
        var out = Data([cla, ins, p1, p2])
        if !data.isEmpty {
            out.append(UInt8(data.count))
            out.append(data)
        }
        if let le {
            out.append(UInt8(le & 0xff))
        }
        return out
    }
}

public struct ResponseAPDU: Equatable, Sendable {
    public var data: Data
    public var sw1: UInt8
    public var sw2: UInt8

    public init(data: Data = Data(), sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public var sw: UInt16 { UInt16(sw1) << 8 | UInt16(sw2) }
    public var isOK: Bool { sw == 0x9000 }
}

/// Whatever carries APDUs to the card (CoreNFC on a phone, a fake in tests).
public protocol CardTransport {
    func transmit(_ command: CommandAPDU) async throws -> ResponseAPDU
}
