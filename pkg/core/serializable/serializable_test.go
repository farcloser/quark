package serializable_test

import (
	"testing"

	"github.com/farcloser/quark/pkg/core/serializable"
)

func TestConfigToString_BasicStringFields(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Name  string `quark:"name"`
		Value string `quark:"value"`
	}

	s := testStruct{
		Name:  "foo",
		Value: "bar",
	}

	result := serializable.ConfigToString(s)

	// Default: no separator between key and value
	expected := "namefoo valuebar "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_BooleanFields(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Enabled  bool `quark:"enabled"`
		Disabled bool `quark:"disabled"`
	}

	s := testStruct{
		Enabled:  true,
		Disabled: false,
	}

	result := serializable.ConfigToString(s)

	expected := "enabledtrue disabledfalse "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_BooleanSwap(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Normal  bool `quark:"normal"`
		Swapped bool `quark:"swapped,swap"`
	}

	s := testStruct{
		Normal:  true,
		Swapped: true,
	}

	result := serializable.ConfigToString(s)

	// swapped=true should become false in output
	expected := "normaltrue swappedfalse "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_OmitEmpty_NonEmpty(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Required string `quark:"required"`
		Optional string `quark:"optional,omitempty"`
	}

	s := testStruct{
		Required: "value",
		Optional: "present",
	}

	result := serializable.ConfigToString(s)

	expected := "requiredvalue optionalpresent "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_OmitEmpty_Empty(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Required string `quark:"required"`
		Optional string `quark:"optional,omitempty"`
	}

	s := testStruct{
		Required: "value",
		Optional: "", // should be omitted
	}

	result := serializable.ConfigToString(s)

	expected := "requiredvalue "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_CustomEndOfLine(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
		Name   string `quark:"name"`
		Value  string `quark:"value"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine: "\n",
		},
		Name:  "foo",
		Value: "bar",
	}

	result := serializable.ConfigToString(s)

	expected := "namefoo\nvaluebar\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_CustomKeyValueSeparator(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
		Name   string `quark:"name"`
		Value  string `quark:"value"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine:         " ",
			KeyValueSeparator: "=",
		},
		Name:  "foo",
		Value: "bar",
	}

	result := serializable.ConfigToString(s)

	expected := "name=foo value=bar "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_QuotedValues(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
		Name   string `quark:"name"`
		Value  string `quark:"value"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine:         " ",
			KeyValueSeparator: "=",
			QuotedValues:      true,
		},
		Name:  "foo",
		Value: "bar with spaces",
	}

	result := serializable.ConfigToString(s)

	expected := `name="foo" value="bar with spaces" `
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_Prefix(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
		Name   string `quark:"name"`
		Value  string `quark:"value"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine: " ",
			Prefix:    "--",
		},
		Name:  "foo",
		Value: "bar",
	}

	result := serializable.ConfigToString(s)

	expected := "--namefoo --valuebar "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_FieldsWithoutTags_Ignored(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Tagged   string `quark:"tagged"`
		Untagged string
		Another  string `quark:"another"`
	}

	s := testStruct{
		Tagged:   "value1",
		Untagged: "should be ignored",
		Another:  "value2",
	}

	result := serializable.ConfigToString(s)

	expected := "taggedvalue1 anothervalue2 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_FullConfig(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config   serializable.Config
		Host     string `quark:"host"`
		Port     string `quark:"port,omitempty"`
		Enabled  bool   `quark:"enabled"`
		Insecure bool   `quark:"secure,swap"` // Note: field is Insecure, key is "secure", swapped
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine:         "\n",
			KeyValueSeparator: "=",
			QuotedValues:      true,
			Prefix:            "--",
		},
		Host:     "localhost",
		Port:     "8080",
		Enabled:  true,
		Insecure: true, // swapped, so output will be "secure=false"
	}

	result := serializable.ConfigToString(s)

	expected := "--host=\"localhost\"\n--port=\"8080\"\n--enabled=\"true\"\n--secure=\"false\"\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_EmptyStruct(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine: "\n",
		},
	}

	result := serializable.ConfigToString(s)

	expected := "\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_AllFieldsOmitted(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config   serializable.Config
		Optional string `quark:"optional,omitempty"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine: " ",
		},
		Optional: "",
	}

	result := serializable.ConfigToString(s)

	expected := " "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_MultipleModifiers(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		// Both swap and omitempty on same field
		Flag bool `quark:"flag,swap,omitempty"`
	}

	s := testStruct{
		Flag: false, // swapped becomes true
	}

	result := serializable.ConfigToString(s)

	// swap applies to bool, omitempty only applies to strings
	expected := "flagtrue "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_QuotedValuesEscapesQuotes(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Config serializable.Config
		Value  string `quark:"value"`
	}

	s := testStruct{
		Config: serializable.Config{
			EndOfLine:    " ",
			QuotedValues: true,
		},
		Value: `contains "quotes"`,
	}

	result := serializable.ConfigToString(s)

	// %q format escapes inner quotes, no separator so key"value"
	expected := `value"contains \"quotes\"" `
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}
