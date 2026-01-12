package format

import (
	"fmt"
	"strings"
)

const defaultTableWidth = 80

// TableConfig configures table output formatting.
type TableConfig struct {
	Title    string // Title displayed at top (e.g., "IMAGE AUDIT RESULTS")
	EmptyMsg string // Message when no rows (e.g., "No image issues found")
	Width    int    // Table width for separators (default 80)
}

// Table formats a slice of items as a text table.
// The rowFn callback extracts display columns and optional detail lines from each item.
// Returns a formatted string with title, rows, and summary.
func Table[T any](
	cfg TableConfig,
	items []T,
	rowFn func(T) (columns, details []string),
) string {
	if len(items) == 0 {
		return cfg.EmptyMsg + "\n"
	}

	width := cfg.Width
	if width <= 0 {
		width = defaultTableWidth
	}

	var builder strings.Builder

	// Header
	_, _ = builder.WriteString(cfg.Title + "\n")
	_, _ = builder.WriteString(strings.Repeat("=", width) + "\n\n")

	// Rows
	for _, item := range items {
		columns, details := rowFn(item)

		// Primary line: join columns with " - "
		if len(columns) > 0 {
			_, _ = builder.WriteString(strings.Join(columns, " - ") + "\n")
		}

		// Detail lines
		for _, detail := range details {
			_, _ = builder.WriteString(fmt.Sprintf("  %s\n", detail))
		}

		_, _ = builder.WriteString("\n")
	}

	// Footer
	_, _ = builder.WriteString(strings.Repeat("=", width) + "\n")
	_, _ = builder.WriteString(fmt.Sprintf("Total: %d\n", len(items)))

	return builder.String()
}

// Section represents a group of items with an optional header.
type Section[T any] struct {
	Header string // Optional section header (e.g., "Target: linux/amd64")
	Items  []T
}

// SectionedTable formats grouped items as a text table with section headers.
// Each section can have its own header, and items are formatted using rowFn.
// Returns total item count across all sections.
func SectionedTable[T any](
	cfg TableConfig,
	sections []Section[T],
	rowFn func(T) (columns, details []string),
) string {
	// Count total items
	total := 0
	for _, section := range sections {
		total += len(section.Items)
	}

	if total == 0 {
		return cfg.EmptyMsg + "\n"
	}

	width := cfg.Width
	if width <= 0 {
		width = defaultTableWidth
	}

	var builder strings.Builder

	// Header
	_, _ = builder.WriteString(cfg.Title + "\n")
	_, _ = builder.WriteString(strings.Repeat("=", width) + "\n\n")

	// Sections
	for _, section := range sections {
		if len(section.Items) == 0 {
			continue
		}

		// Section header
		if section.Header != "" {
			_, _ = builder.WriteString(section.Header + "\n")
			_, _ = builder.WriteString(strings.Repeat("-", width) + "\n")
		}

		// Rows within section
		for _, item := range section.Items {
			columns, details := rowFn(item)

			if len(columns) > 0 {
				_, _ = builder.WriteString(strings.Join(columns, " - ") + "\n")
			}

			for _, detail := range details {
				_, _ = builder.WriteString(fmt.Sprintf("  %s\n", detail))
			}

			_, _ = builder.WriteString("\n")
		}
	}

	// Footer
	_, _ = builder.WriteString(strings.Repeat("=", width) + "\n")
	_, _ = builder.WriteString(fmt.Sprintf("Total: %d\n", total))

	return builder.String()
}
