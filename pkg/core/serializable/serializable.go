package serializable

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	tag       = "quark"
	omitempty = "omitempty"
	swap      = "swap"
)

// Config defines the type of serializer we want.
// Allows customizing EOL, key value separators, whether values are quoted or not, and key prefix.
type Config struct {
	EndOfLine         string
	KeyValueSeparator string
	QuotedValues      bool
	Prefix            string
}

// ConfigToString serializes any interface, possibly honoring provided Config.
// Otherwise, defaults to space for EOL, no key-value separator, not quoted, no prefix.
func ConfigToString(cnf any) string {
	baseConfigType := reflect.ValueOf(Config{}).Type()
	com := []string{}
	endofline := " "
	kvsep := ""
	quoted := false
	prefix := ""

	objectValue := reflect.ValueOf(cnf)
	typeOf := objectValue.Type()

	for i := range objectValue.NumField() {
		fieldValue := objectValue.Field(i)

		fieldTag := typeOf.Field(i).Tag.Get(tag)
		if fieldTag == "" {
			if fieldValue.Type().ConvertibleTo(baseConfigType) {
				endofline = fieldValue.Interface().(Config).EndOfLine     //nolint:forcetypeassert
				kvsep = fieldValue.Interface().(Config).KeyValueSeparator //nolint:forcetypeassert
				quoted = fieldValue.Interface().(Config).QuotedValues     //nolint:forcetypeassert
				prefix = fieldValue.Interface().(Config).Prefix           //nolint:forcetypeassert
			}

			continue
		}

		qual := strings.Split(fieldTag, ",")
		key := qual[0]
		ommitter := false
		swapper := false

		for _, v := range qual {
			switch v {
			case omitempty:
				ommitter = true
			case swap:
				swapper = true
			default:
			}
		}

		finalValue := ""

		if fieldValue.Type().Kind() == reflect.Bool {
			boolValue := fieldValue.Bool()
			if swapper {
				boolValue = !boolValue
			}

			finalValue = strconv.FormatBool(boolValue)
		} else if fieldValue.Type().Kind() == reflect.String {
			finalValue = fieldValue.String()
			if finalValue == "" && ommitter {
				continue
			}
		}

		if quoted {
			com = append(com, fmt.Sprintf(`%s%s%s%q`, prefix, key, kvsep, finalValue))
		} else {
			com = append(com, fmt.Sprintf(`%s%s%s%s`, prefix, key, kvsep, finalValue))
		}
	}

	return strings.Join(com, endofline) + endofline
}
