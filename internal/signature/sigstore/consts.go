package sigstore

import "github.com/farcloser/quark/internal/types"

// =============================================================================
// Annotation Keys
// =============================================================================

/*
  Complete full-blown madness below:

  OCI Manifest
  └── layers[].mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"
      └── Bundle
          └── mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"
              └── dsseEnvelope
                  └── payloadType: "application/vnd.in-toto+json"
                      └── Statement
                          ├── _type: "https://in-toto.io/Statement/v1"
                          └── predicateType: "https://sigstore.dev/cosign/sign/v1"

  And each one is a different format:
  - OCI: IANA-style media type
  - Bundle: IANA-style media type (duplicated)
  - DSSE: IANA-style media type
  - Statement _type: URL
  - predicateType: URL

  Welcome to the glorious world of "extensible" specifications designed by committee.
*/

const (
	// Legacy cosign signature (simple signing payload)
	layerMediaTypeCosignSignature types.MediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

	// Legacy cosign attestation (raw DSSE envelope)
	layerMediaTypeDSSEEnvelope types.MediaType = "application/vnd.dsse.envelope.v1+json"

	// Current sigStore bundle format
	layerMediaTypeSigstoreBundle types.MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// Payload types: not particularly useful, we just parse
	// payloadTypeInToto = "application/vnd.in-toto+json"

	// Statement types: signing verification does that on its own
	// statementTypeInToto = "https://in-toto.io/Statement/v1"

	// Predicate types
	predicateTypeSignature      = "https://sigstore.dev/cosign/sign/v1"
	predicateTypeSLSAProvenance = "https://slsa.dev/provenance" // /v1
	// predicateTypeSPDX           = "https://spdx.dev/Document"   // /v2.3
	predicateTypeCycloneDX = "https://cyclonedx.org/bom" // /v1.4
	predicateTypeVuln      = "https://cosign.sigstore.dev/attestation/vuln/v1"

	//| Predicate            | URI                                                       |
	//|----------------------|-----------------------------------------------------------|
	//| SLSA Provenance      | https://slsa.dev/provenance/v1                            |
	//| SPDX SBOM            | https://spdx.dev/Document/v2.3                            |
	//| CycloneDX SBOM       | https://cyclonedx.org/bom/v1.4                            |
	//| SCAI Report          | https://in-toto.io/attestation/scai/attribute-report/v0.2 |
	//| Verification Summary | https://slsa.dev/verification_summary/v1                  |
	//| Runtime Traces       | https://in-toto.io/attestation/runtime-trace/v0.1         |
	//| Release              | https://in-toto.io/attestation/release/v0.1               |
	//| Test Result          | https://in-toto.io/attestation/test-result/v0.1           |

	// Tier 1:
	// SLSA Provenance How it was built (inputs, builder, params)
	// SBOM What's inside (components, dependencies)
	// VEX Is vuln X exploitable?
	// VSA (Verification Summary Attestation) — an attestation that says "I already verified this, trust me."
	//

	// Tier 2:
	// Runtime Traces - requires eBPF monitoring during build - basically trace logs - Tetragon + capable kernel
	// Release - Makes sense conceptually — separates "built by X" from "published by Y." But v0.1, minimal adoption.
	// npm has its own format. PyPI, Maven, Docker Hub don't use it. Spec exists, ecosystem doesn't care yet.

	// cilium/ebpf for a base:
	/*
				SEC("kprobe/tcp_connect")
				int trace_tcp_connect(struct pt_regs *ctx) {
				    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

				    struct event e = {};
				    e.pid = bpf_get_current_pid_tgid() >> 32;
				    bpf_get_current_comm(&e.comm, sizeof(e.comm));

				    // Extract destination IP/port from sock struct
				    bpf_probe_read(&e.daddr, sizeof(e.daddr), &sk->__sk_common.skc_daddr);
				    bpf_probe_read(&e.dport, sizeof(e.dport), &sk->__sk_common.skc_dport);

				    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
				    return 0;
				}


			func main() {
			    objs := probeObjects{}
			    loadProbeObjects(&objs, nil)

			    kp, _ := link.Kprobe("tcp_connect", objs.TraceTcpConnect, nil)
			    defer kp.Close()

			    rd, _ := perf.NewReader(objs.Events, os.Getpagesize())
			    for {
			        record, _ := rd.Read()
			        // Parse event, log it, attest to it
			    }
			}

		// Or just...
		strace -f -e trace=network -o build-network.log docker build .
	*/

	// Tier 3: academic, immature tooling
	// SCAI What attributes does this artifact have? eg: gcc hardening, etc
	// Links Ignore - legacy

	// eBPF: Tetragon or Falco
)

// reservedAnnotationPrefixes are annotation prefixes used by sigstore/cosign internally.
//
//nolint:gochecknoglobals // Package-level constant for annotation filtering.
var reservedAnnotationPrefixes = []string{
	"dev.sigstore.cosign/",
	// Legacy
	"dev.cosignproject.cosign/",
}
