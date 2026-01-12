package git

const (
	// maxSSHStringLen is the maximum allowed length for SSH string fields.
	// SSH signature fields (public keys, signatures) should never exceed this.
	maxSSHStringLen = 64 * 1024 // 64KB
	sshSigMagicLen  = len(sshSigMagic)

	sshSigMagic     = "SSHSIG"
	sshSigVersion   = 1
	sshSigNamespace = "git"
	sshSigHashAlgo  = "sha512"

	// armorLineLength is the maximum line length for base64-encoded SSH signatures.
	armorLineLength = 70
)
