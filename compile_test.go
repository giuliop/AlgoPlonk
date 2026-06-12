package algoplonk_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
)

type compileTestCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *compileTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	return nil
}

func TestCompileRejectsUnknownSetup(t *testing.T) {
	_, err := ap.Compile(&compileTestCircuit{}, ecc.BN254, setup.Name(999))
	if err == nil {
		t.Fatal("expected unknown setup error")
	}
	if !strings.Contains(err.Error(), "unknown setup") {
		t.Fatalf("unexpected error: %v", err)
	}
}
