package format_test

import (
	"strings"
	"testing"

	"github.com/farcloser/quark/pkg/dev/format"
)

func TestTable_EmptyItems(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "TEST RESULTS",
		EmptyMsg: "No items found",
		Width:    80,
	}

	result := format.Table(cfg, []string{}, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	expected := "No items found\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestTable_WithItems(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "TEST RESULTS",
		EmptyMsg: "No items found",
		Width:    40,
	}

	items := []string{"item1", "item2"}

	result := format.Table(cfg, items, func(s string) ([]string, []string) {
		return []string{s, "col2"}, nil
	})

	if !strings.Contains(result, "TEST RESULTS") {
		t.Error("expected title in output")
	}

	if !strings.Contains(result, "item1 - col2") {
		t.Error("expected first row with columns")
	}

	if !strings.Contains(result, "item2 - col2") {
		t.Error("expected second row with columns")
	}

	if !strings.Contains(result, "Total: 2") {
		t.Error("expected total count in footer")
	}

	// Check separator width
	if !strings.Contains(result, strings.Repeat("=", 40)) {
		t.Error("expected separator with configured width")
	}
}

func TestTable_WithDetails(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "DETAILS TEST",
		EmptyMsg: "Empty",
		Width:    80,
	}

	items := []string{"main"}

	result := format.Table(cfg, items, func(s string) ([]string, []string) {
		return []string{s}, []string{"detail1", "detail2"}
	})

	if !strings.Contains(result, "  detail1") {
		t.Error("expected indented detail1")
	}

	if !strings.Contains(result, "  detail2") {
		t.Error("expected indented detail2")
	}
}

func TestTable_DefaultWidth(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "DEFAULT WIDTH",
		EmptyMsg: "Empty",
		// Width not set, should default to 80
	}

	items := []string{"item"}

	result := format.Table(cfg, items, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	// Default width is 80
	if !strings.Contains(result, strings.Repeat("=", 80)) {
		t.Error("expected separator with default width 80")
	}
}

func TestTable_ZeroWidth(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "ZERO WIDTH",
		EmptyMsg: "Empty",
		Width:    0, // Should use default 80
	}

	items := []string{"item"}

	result := format.Table(cfg, items, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	// Zero width should default to 80
	if !strings.Contains(result, strings.Repeat("=", 80)) {
		t.Error("expected separator with default width 80 when width is 0")
	}
}

func TestSectionedTable_EmptySections(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "SECTIONED RESULTS",
		EmptyMsg: "No items in any section",
		Width:    80,
	}

	sections := []format.Section[string]{}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	expected := "No items in any section\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSectionedTable_AllEmptySections(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "SECTIONED RESULTS",
		EmptyMsg: "No items in any section",
		Width:    80,
	}

	sections := []format.Section[string]{
		{Header: "Section 1", Items: []string{}},
		{Header: "Section 2", Items: []string{}},
	}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	expected := "No items in any section\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSectionedTable_WithSections(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "SECTIONED RESULTS",
		EmptyMsg: "Empty",
		Width:    50,
	}

	sections := []format.Section[string]{
		{Header: "Group A", Items: []string{"a1", "a2"}},
		{Header: "Group B", Items: []string{"b1"}},
	}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	if !strings.Contains(result, "SECTIONED RESULTS") {
		t.Error("expected title")
	}

	if !strings.Contains(result, "Group A") {
		t.Error("expected section header Group A")
	}

	if !strings.Contains(result, "Group B") {
		t.Error("expected section header Group B")
	}

	if !strings.Contains(result, "a1") {
		t.Error("expected item a1")
	}

	if !strings.Contains(result, "b1") {
		t.Error("expected item b1")
	}

	// Total should be 3 (2 + 1)
	if !strings.Contains(result, "Total: 3") {
		t.Error("expected total count 3")
	}

	// Section separator
	if !strings.Contains(result, strings.Repeat("-", 50)) {
		t.Error("expected section separator")
	}
}

func TestSectionedTable_MixedEmptyNonEmpty(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "MIXED SECTIONS",
		EmptyMsg: "Empty",
		Width:    80,
	}

	sections := []format.Section[string]{
		{Header: "Empty Section", Items: []string{}},
		{Header: "Has Items", Items: []string{"item1"}},
		{Header: "Also Empty", Items: []string{}},
	}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	// Empty sections should not appear
	if strings.Contains(result, "Empty Section") {
		t.Error("empty section header should not appear")
	}

	if strings.Contains(result, "Also Empty") {
		t.Error("empty section header should not appear")
	}

	// Non-empty section should appear
	if !strings.Contains(result, "Has Items") {
		t.Error("expected non-empty section header")
	}

	if !strings.Contains(result, "item1") {
		t.Error("expected item1")
	}

	if !strings.Contains(result, "Total: 1") {
		t.Error("expected total count 1")
	}
}

func TestSectionedTable_NoSectionHeader(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "NO HEADERS",
		EmptyMsg: "Empty",
		Width:    80,
	}

	sections := []format.Section[string]{
		{Header: "", Items: []string{"item1", "item2"}},
	}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s}, nil
	})

	// Should not have section separator when no header
	lines := strings.Split(result, "\n")

	dashLineCount := 0

	for _, line := range lines {
		if line == strings.Repeat("-", 80) {
			dashLineCount++
		}
	}

	if dashLineCount != 0 {
		t.Errorf("expected no dash separators when section has no header, got %d", dashLineCount)
	}
}

func TestSectionedTable_WithDetails(t *testing.T) {
	t.Parallel()

	cfg := format.TableConfig{
		Title:    "WITH DETAILS",
		EmptyMsg: "Empty",
		Width:    80,
	}

	sections := []format.Section[string]{
		{Header: "Section", Items: []string{"main"}},
	}

	result := format.SectionedTable(cfg, sections, func(s string) ([]string, []string) {
		return []string{s, "extra"}, []string{"detail line"}
	})

	if !strings.Contains(result, "main - extra") {
		t.Error("expected columns joined with ' - '")
	}

	if !strings.Contains(result, "  detail line") {
		t.Error("expected indented detail line")
	}
}
