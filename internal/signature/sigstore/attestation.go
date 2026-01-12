package sigstore

import (
	"github.com/farcloser/quark/internal/types"
)

type sigstoreAttestation struct {
	sigstoreBundle

	statement *types.Statement
}

func (sa *sigstoreAttestation) Payload() *types.Statement {
	return sa.statement
}
