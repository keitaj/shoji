import Foundation
import Testing

@testable import ShojiProverKit

/// Proves the mock fixture end to end. Needs the files that `make circuit` and a
/// first `bb` run leave on a development machine, and is skipped without them:
///   SHOJI_TEST_DIR/shoji.json, vk, inputs.json, g1.dat
struct ProverTests {
    static let dir = ProcessInfo.processInfo.environment["SHOJI_TEST_DIR"].map { URL(fileURLWithPath: $0) }

    @Test(.enabled(if: ProverTests.dir != nil))
    func testProvesTheMockFixture() throws {
        let dir = try #require(Self.dir)
        let load = { (name: String) in try Data(contentsOf: dir.appendingPathComponent(name)) }
        let proof = try Prover.prove(
            circuit: load("shoji.json"), inputs: load("inputs.json"), srs: load("g1.dat"), verificationKey: load("vk"))
        #expect(proof.proof.count == 14656)
        #expect(proof.publicInputs.count == 7 * 32)
        // is_over_threshold is the last public value and must be 1 for the adult fixture.
        #expect(proof.publicValue(6)?.last == 1)
        try proof.proof.write(to: dir.appendingPathComponent("proof"))
        try proof.publicInputs.write(to: dir.appendingPathComponent("public_inputs"))
    }

    @Test(.enabled(if: ProverTests.dir != nil))
    func testReportsUnsatisfiedInputsWithoutEchoingThem() throws {
        let dir = try #require(Self.dir)
        let load = { (name: String) in try Data(contentsOf: dir.appendingPathComponent(name)) }
        var inputs = try JSONSerialization.jsonObject(with: load("inputs.json")) as! [String: Any]
        var sig = inputs["nonce_sig"] as! [Int]
        sig[0] ^= 1
        inputs["nonce_sig"] = sig
        #expect(throws: Prover.ProverError(description: "inputs do not satisfy the circuit")) {
            try Prover.prove(
                circuit: load("shoji.json"), inputs: JSONSerialization.data(withJSONObject: inputs),
                srs: load("g1.dat"), verificationKey: load("vk"))
        }
    }
}
