package setup_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/giuliop/algoplonk/setup"
)

type setupTestCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *setupTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	return nil
}

func TestRunRejectsUnknownSetup(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder,
		&setupTestCircuit{})
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	_, _, err = setup.Run(ccs, setup.Name(999))
	if err == nil {
		t.Fatal("expected unknown setup error")
	}
	if !strings.Contains(err.Error(), "unknown setup") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := setup.Get(setup.Name(999)); ok {
		t.Fatal("unexpected setup metadata for unknown setup")
	}
}
