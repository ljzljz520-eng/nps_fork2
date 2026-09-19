package credential

import "strings"

// MaskedMarker replaces secret material in default exports.
const MaskedMarker = "********"

// MaskSecret hides a secret for export. Empty values stay empty (so consumers
// can distinguish "unset" from "present but hidden"), short values are fully
// masked, and longer values retain a short non-sensitive prefix to aid support
// without revealing the credential.
func MaskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if IsEnvelope(value) || IsPasswordHash(value) || len(value) <= 4 {
		return MaskedMarker
	}
	return value[:2] + MaskedMarker
}
