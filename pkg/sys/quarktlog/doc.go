// Package quarktlog provides the tlog specific to quark usage.
// Quark defines domain specific entry types on top of the core tlog entry types.
package quarktlog

/*

API to implement.

type TransparencyLog struct {
	Provider Upstream
	SigningIdentity
	OrgName string
}

func (tl *TransparencyLog) Open()
-> calls Open(path string, opts ...Option) (*Log, error)
with path = user_datadir/quark/org_name/tlog
-> if fails, calls Clone(ctx, tl.Provider.URL(organizationName, "tlog"), tl.Provider.AccessIdentity())
-> if fails, calls Init(ctx, path, gen)
with gen = {
	Root: tl.SigningIdentity()
}

type Upstream interface {
	URL(org, repo)
	AccessIdentity()
	...
}

var GitHub Upstream
var GitLab Upstream


func (tl *TransparencyLog) TrustAdmin(signer)
func (tl *TransparencyLog) Trust(signer)
func (tl *TransparencyLog) Revoke(signer, cutDate)

UntrustedOperations(fromSigner) []*Entries
TrustedOperations(fromSigner) []*Entries
AllOperations(fromSigner) []*Entries

*/
