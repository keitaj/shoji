import Foundation
import ShojiProverKit

/// Loads the proving material bundled with the app and runs the prover.
enum OnDeviceProver {
    struct Material {
        let circuit: Data
        let verificationKey: Data
        let srs: Data
    }

    struct Measurement {
        let seconds: Double
        /// Peak physical memory footprint of the app so far, in MiB.
        let peakMiB: Double
        let proof: Prover.Proof
    }

    static func resource(_ name: String) throws -> Data {
        guard let dir = Bundle.main.url(forResource: "ProverResources", withExtension: nil) else {
            throw Prover.ProverError(description: "the app was built without ProverResources")
        }
        return try Data(contentsOf: dir.appendingPathComponent(name), options: .mappedIfSafe)
    }

    static func loadMaterial() throws -> Material {
        Material(circuit: try resource("shoji.json"), verificationKey: try resource("vk"), srs: try resource("g1.dat"))
    }

    /// Proves once and reports how long it took and the peak memory footprint.
    static func measure(inputs: Data, material: Material) throws -> Measurement {
        let start = Date()
        let proof = try Prover.prove(
            circuit: material.circuit, inputs: inputs, srs: material.srs, verificationKey: material.verificationKey)
        return Measurement(seconds: Date().timeIntervalSince(start), peakMiB: peakFootprintMiB(), proof: proof)
    }

    /// The process's peak physical footprint, the number iOS memory limits apply to.
    static func peakFootprintMiB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return -1 }
        return Double(info.ledger_phys_footprint_peak) / 1_048_576
    }

    /// Benchmark with the bundled mock inputs (synthetic data). Returns a report and
    /// the last proof, so that it can be checked with `bb verify` on a PC.
    static func benchmark(runs: Int) -> (report: String, last: Prover.Proof?) {
        var lines: [String] = []
        var last: Prover.Proof?
        do {
            let material = try loadMaterial()
            let inputs = try resource("bench_inputs.json")
            lines.append("device: \(deviceModel()), iOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
            lines.append("cores: \(ProcessInfo.processInfo.activeProcessorCount), memory: \(ProcessInfo.processInfo.physicalMemory / 1_048_576) MiB")
            for run in 1...runs {
                let m = try measure(inputs: inputs, material: material)
                lines.append(String(format: "run %d: %.2f s, peak footprint %.0f MiB, proof %d bytes", run, m.seconds, m.peakMiB, m.proof.proof.count))
                last = m.proof
            }
        } catch {
            lines.append("failed: \(error)")
        }
        return (lines.joined(separator: "\n"), last)
    }

    static func deviceModel() -> String {
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &buf, &size, nil, 0)
        return String(cString: buf)
    }
}
