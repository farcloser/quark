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

// Tests for numeric types.

func TestConfigToString_IntTypes(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Count int `quark:"count"`
	}

	s := testStruct{
		Count: 42,
	}

	result := serializable.ConfigToString(s)

	expected := "count42 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_NegativeInt(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Value int `quark:"value"`
	}

	s := testStruct{
		Value: -123,
	}

	result := serializable.ConfigToString(s)

	expected := "value-123 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_UintType(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Port uint16 `quark:"port"`
	}

	s := testStruct{
		Port: 8080,
	}

	result := serializable.ConfigToString(s)

	expected := "port8080 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_Float64Type(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Ratio float64 `quark:"ratio"`
	}

	s := testStruct{
		Ratio: 3.14,
	}

	result := serializable.ConfigToString(s)

	expected := "ratio3.14 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_Float32Type(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Value float32 `quark:"value"`
	}

	s := testStruct{
		Value: 2.5,
	}

	result := serializable.ConfigToString(s)

	expected := "value2.5 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

// Tests for unsupported types - documenting current behavior.
// The serializable package supports string, bool, int, uint, and float types.
// Unsupported types (slices, maps, structs, pointers) produce empty string values.

func TestConfigToString_UnsupportedType_Slice(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Items []string `quark:"items"`
	}

	s := testStruct{
		Items: []string{"a", "b", "c"},
	}

	result := serializable.ConfigToString(s)

	// Slice fields produce empty value (unsupported type)
	expected := "items "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_UnsupportedType_Map(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Data map[string]string `quark:"data"`
	}

	s := testStruct{
		Data: map[string]string{"key": "value"},
	}

	result := serializable.ConfigToString(s)

	// Map fields produce empty value (unsupported type)
	expected := "data "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_UnsupportedType_NestedStruct(t *testing.T) {
	t.Parallel()

	type nested struct {
		Inner string
	}

	type testStruct struct {
		Nested nested `quark:"nested"`
	}

	s := testStruct{
		Nested: nested{Inner: "value"},
	}

	result := serializable.ConfigToString(s)

	// Nested struct fields produce empty value (unsupported type)
	expected := "nested "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_UnsupportedType_Pointer(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Ptr *string `quark:"ptr"`
	}

	value := "pointed"
	s := testStruct{
		Ptr: &value,
	}

	result := serializable.ConfigToString(s)

	// Pointer fields produce empty value (unsupported type)
	expected := "ptr "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_UnsupportedType_NilPointer(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Ptr *string `quark:"ptr"`
	}

	s := testStruct{
		Ptr: nil,
	}

	result := serializable.ConfigToString(s)

	// Nil pointer fields produce empty value (unsupported type)
	expected := "ptr "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestConfigToString_AllScalarTypes(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		Name    string  `quark:"name"`
		Count   int     `quark:"count"`
		Enabled bool    `quark:"enabled"`
		Ratio   float64 `quark:"ratio"`
	}

	s := testStruct{
		Name:    "test",
		Count:   42,
		Enabled: true,
		Ratio:   3.14,
	}

	result := serializable.ConfigToString(s)

	// All scalar types work
	expected := "nametest count42 enabledtrue ratio3.14 "
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}
