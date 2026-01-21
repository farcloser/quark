package sigstore

import (
	"log/slog"

	"github.com/farcloser/quark/internal/types"
)

type sigstoreSignature struct {
	sigstoreBundle
}

func (cs *sigstoreSignature) Digests() []types.Digest {
	subjects := cs.statement.GetSubject()

	digests := []types.Digest{}

	for _, subject := range subjects {
		// FIXME: generalize to other digests types
		if dgst, ok := subject.GetDigest()["sha256"]; ok {
			digests = append(digests, types.Digest(dgst))
		} else {
			slog.Warn("subject has no recognized digest", "digest", subject.GetDigest())
		}
	}

	return digests
}
