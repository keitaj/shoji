// Package prover runs the holder-side toolchain: witness generation with
// noir-execute and proof generation with bb. For now this runs on a PC as a
// stand-in for the phone.
package prover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/keitaj/shoji/internal/witness"
)

// VerifierTarget selects bb's transcript hash and zero-knowledge setting. Prover
// and verifier must agree. This target is zero-knowledge; never switch to one of
// the "-no-zk" targets, which would leak the witness.
const VerifierTarget = "noir-recursive"

// Tools locates the binaries and circuit artifacts.
type Tools struct {
	NoirExecute string // path to noir-execute
	BB          string // path to bb
	Artifact    string // circuits/target/shoji.json
	VK          string // verification key written by `bb write_vk`
}

// DefaultTools resolves tools from PATH (falling back to the default install
// locations) and artifacts relative to the repository root.
func DefaultTools(repoRoot string) Tools {
	home, _ := os.UserHomeDir()
	find := func(name, fallback string) string {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		return filepath.Join(home, fallback)
	}
	return Tools{
		NoirExecute: find("noir-execute", ".nargo/bin/noir-execute"),
		BB:          find("bb", ".bb/bb"),
		Artifact:    filepath.Join(repoRoot, "circuits", "target", "shoji.json"),
		VK:          filepath.Join(repoRoot, "circuits", "target", "vk", "vk"),
	}
}

// Proof is what the holder sends to the verifier, plus the public inputs bb
// wrote (used by tests; the verifier rebuilds them itself).
type Proof struct {
	Proof        []byte
	PublicInputs []byte
}

// ErrUnsatisfied means the inputs do not satisfy the circuit.
var ErrUnsatisfied = errors.New("inputs do not satisfy the circuit")

// Prove generates a proof. The witness lives only in a private temporary
// directory that is removed before returning.
func Prove(ctx context.Context, t Tools, in *witness.Inputs) (*Proof, error) {
	dir, err := os.MkdirTemp("", "shoji-prove-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	proverFile := filepath.Join(dir, "Prover.toml")
	if err := os.WriteFile(proverFile, []byte(in.ProverTOML()), 0o600); err != nil {
		return nil, err
	}
	// Tool output is discarded on purpose: it can echo witness values.
	if err := exec.CommandContext(ctx, t.NoirExecute, "execute",
		"--artifact-path", t.Artifact, "--prover-file", proverFile,
		"--output-dir", dir, "--witness-name", "witness").Run(); err != nil {
		return nil, ErrUnsatisfied
	}
	out := filepath.Join(dir, "out")
	if err := exec.CommandContext(ctx, t.BB, "prove",
		"-b", t.Artifact, "-w", filepath.Join(dir, "witness.gz"),
		"-k", t.VK, "-o", out, "-t", VerifierTarget).Run(); err != nil {
		return nil, fmt.Errorf("bb prove failed: %w", err)
	}
	proof, err := os.ReadFile(filepath.Join(out, "proof"))
	if err != nil {
		return nil, err
	}
	pub, err := os.ReadFile(filepath.Join(out, "public_inputs"))
	if err != nil {
		return nil, err
	}
	return &Proof{Proof: proof, PublicInputs: pub}, nil
}
