// Package sigstore implements signature related interfaces (Root, Signer, Signature, Attestation), for both
// verification and generation. It is meant to be used on payloads retrieved from OCI manifests, and does not interact
// with network (except for Root network initialization).
package sigstore
