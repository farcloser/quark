package v1

import (
	"fmt"

	"github.com/farcloser/quark/pkg/sys/tlog"
)

// entryEnvelope is used for type discrimination during unmarshaling.
type entryEnvelope struct {
	Type    string `json:"type"`
	Version int    `json:"version"` // for genesis version checking
}

// parseEntry parses a JSON-encoded log entry and returns the appropriate Entry type.
func parseEntry(data []byte) (Entry, error) {
	var env entryEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", tlog.ErrInvalidEntry, err)
	}

	var entry Entry

	var err error

	switch env.Type {
	case tlog.TypeGenesis:
		entry, err = parseGenesis(data, env.Version)
	case tlog.TypeEvent:
		entry, err = parseInto[tlog.EventEntry](data)
	case tlog.TypeTrustAdmin:
		entry, err = parseInto[tlog.TrustAdminEntry](data)
	case tlog.TypeTrustSigner:
		entry, err = parseInto[tlog.TrustSignerEntry](data)
	case tlog.TypeRevokeAdmin:
		entry, err = parseInto[tlog.RevokeAdminEntry](data)
	case tlog.TypeRevokeSigner:
		entry, err = parseInto[tlog.RevokeSignerEntry](data)
	default:
		return nil, fmt.Errorf("%w: %s", tlog.ErrUnknownEntryType, env.Type)
	}

	if err != nil {
		return nil, err
	}

	return entry, nil
}

// parseInto is a generic helper for unmarshaling entry types.
func parseInto[T any](data []byte) (*T, error) {
	var entry T
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("%w: %w", tlog.ErrInvalidEntry, err)
	}

	return &entry, nil
}

// parseGenesis handles version-specific parsing for genesis entries.
func parseGenesis(data []byte, version int) (*tlog.GenesisEntry, error) {
	switch version {
	case 1:
		return parseInto[tlog.GenesisEntry](data)
	// Future versions would be handled here:
	// case 2:
	//     return translateGenesisV2toV1(parseGenesisV2(data))
	default:
		return nil, fmt.Errorf("%w: %d", tlog.ErrUnsupportedVersion, version)
	}
}

// marshalEntry serializes an Entry to JSON with the type field.
func marshalEntry(entry Entry) ([]byte, error) {
	result, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tlog.ErrInvalidEntry, err)
	}

	return result, nil
}
