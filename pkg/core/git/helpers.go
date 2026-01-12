package git

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/fault"
)

// buildSSHSignedData constructs the data blob that gets signed.
// This matches Git's SSH signature verification expectations.
func buildSSHSignedData(namespace, hashAlgo string, content []byte) []byte {
	// Hash the content with SHA512.
	hasher := sha512.New()
	_, _ = hasher.Write(content) // sha512 never returns error
	hashBytes := hasher.Sum(nil)

	// Build the signed data structure.
	// Format: MAGIC + NAMESPACE + RESERVED + HASH_ALGO + HASH
	var buf bytes.Buffer

	_, _ = buf.WriteString(sshSigMagic)
	writeSSHString(&buf, []byte(namespace))
	writeSSHString(&buf, nil) // reserved
	writeSSHString(&buf, []byte(hashAlgo))
	writeSSHString(&buf, hashBytes)

	return buf.Bytes()
}

// armorSSHSignature armors the signature blob in PEM-like format.
func armorSSHSignature(blob []byte) []byte {
	var buf bytes.Buffer

	_, _ = buf.WriteString("-----BEGIN SSH SIGNATURE-----\n")

	encoded := base64.StdEncoding.EncodeToString(blob)
	for i := 0; i < len(encoded); i += armorLineLength {
		end := min(i+armorLineLength, len(encoded))

		_, _ = buf.WriteString(encoded[i:end])
		_, _ = buf.WriteString("\n")
	}

	_, _ = buf.WriteString("-----END SSH SIGNATURE-----")

	return buf.Bytes()
}

// dearmorSSHSignature parses a PEM-armored SSH signature.
func dearmorSSHSignature(armored string) ([]byte, error) {
	const begin = "-----BEGIN SSH SIGNATURE-----"

	const end = "-----END SSH SIGNATURE-----"

	start := strings.Index(armored, begin)
	if start == -1 {
		return nil, ErrSignatureMissingBeginMarker
	}

	stop := strings.Index(armored, end)
	if stop == -1 {
		return nil, ErrSignatureMissingEndMarker
	}

	contentStart := start + len(begin)
	if stop <= contentStart {
		return nil, ErrSignatureMalformedArmor
	}

	b64 := armored[contentStart:stop]
	b64 = strings.ReplaceAll(b64, "\n", "")
	b64 = strings.ReplaceAll(b64, " ", "")

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureMalformedB64, err)
	}

	return decoded, nil
}

// buildSSHSignatureBlob builds the full signature blob.
func buildSSHSignatureBlob(pubKey ssh.PublicKey, sig *ssh.Signature) []byte {
	var buf bytes.Buffer

	// Magic preamble.
	_, _ = buf.WriteString(sshSigMagic)

	// Version.
	_ = binary.Write(&buf, binary.BigEndian, uint32(sshSigVersion))

	// Public key.
	writeSSHString(&buf, pubKey.Marshal())

	// Namespace.
	writeSSHString(&buf, []byte(sshSigNamespace))

	// Reserved.
	writeSSHString(&buf, nil)

	// Hash algorithm.
	writeSSHString(&buf, []byte(sshSigHashAlgo))

	// Signature.
	writeSSHString(&buf, ssh.Marshal(sig))

	return buf.Bytes()
}

// parseSSHSignatureBlob parses the SSH signature blob.
//
//nolint:revive // 4 return values is appropriate for parsing functions
func parseSSHSignatureBlob(data []byte) (ssh.PublicKey, string, *ssh.Signature, error) {
	if len(data) < sshSigMagicLen || string(data[:sshSigMagicLen]) != sshSigMagic {
		return nil, "", nil, ErrSignatureInvalidMagic
	}

	reader := bytes.NewReader(data[sshSigMagicLen:])

	// Version.
	var version uint32
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return nil, "", nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	if version != sshSigVersion {
		return nil, "", nil, fmt.Errorf("%w: %d", ErrSignatureUnsupportedVersion, version)
	}

	// Public key.
	pubKeyData, err := readSSHString(reader)
	if err != nil {
		return nil, "", nil, err
	}

	pubKey, err := ssh.ParsePublicKey(pubKeyData)
	if err != nil {
		return nil, "", nil, fmt.Errorf("%w: %w", ErrSignatureParsePublicKey, err)
	}

	// Namespace.
	namespaceData, err := readSSHString(reader)
	if err != nil {
		return nil, "", nil, err
	}

	namespace := string(namespaceData)

	// Reserved.
	_, err = readSSHString(reader)
	if err != nil {
		return nil, "", nil, err
	}

	// Hash algorithm.
	hashAlgoData, err := readSSHString(reader)
	if err != nil {
		return nil, "", nil, err
	}

	if string(hashAlgoData) != sshSigHashAlgo {
		return nil, "", nil, fmt.Errorf("%w: %q", ErrSignatureUnsupportedHash, hashAlgoData)
	}

	// Signature.
	sigData, err := readSSHString(reader)
	if err != nil {
		return nil, "", nil, err
	}

	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(sigData, sig); err != nil {
		return nil, "", nil, fmt.Errorf("%w: %w", ErrSignatureParseSig, err)
	}

	return pubKey, namespace, sig, nil
}

// writeSSHString writes an SSH string (uint32 length + data).
func writeSSHString(w io.Writer, data []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(data)))
	_, _ = w.Write(data)
}

// readSSHString reads an SSH string (uint32 length + data).
func readSSHString(reader *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	if length > maxSSHStringLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrSignatureStringTooLong, length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return data, nil
}
