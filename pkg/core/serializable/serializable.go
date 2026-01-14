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
	bit32     = 32
	bit64     = 64
	decimal   = 10
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
			// Type assertions are safe here: ConvertibleTo for struct types only returns true
			// if the field is actually a Config struct (or identical unnamed type).
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
		omitter := false
		swapper := false

		for _, v := range qual {
			switch v {
			case omitempty:
				omitter = true
			case swap:
				swapper = true
			default:
			}
		}

		finalValue := ""

		//nolint:exhaustive
		switch fieldValue.Type().Kind() {
		case reflect.Bool:
			boolValue := fieldValue.Bool()
			if swapper {
				boolValue = !boolValue
			}

			finalValue = strconv.FormatBool(boolValue)
		case reflect.String:
			finalValue = fieldValue.String()
			if finalValue == "" && omitter {
				continue
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			finalValue = strconv.FormatInt(fieldValue.Int(), decimal)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			finalValue = strconv.FormatUint(fieldValue.Uint(), decimal)
		case reflect.Float32:
			finalValue = strconv.FormatFloat(fieldValue.Float(), 'f', -1, bit32)
		case reflect.Float64:
			finalValue = strconv.FormatFloat(fieldValue.Float(), 'f', -1, bit64)
		default:
			// Unsupported types (slices, maps, structs, pointers) produce empty values
		}

		if quoted {
			com = append(com, fmt.Sprintf(`%s%s%s%q`, prefix, key, kvsep, finalValue))
		} else {
			com = append(com, fmt.Sprintf(`%s%s%s%s`, prefix, key, kvsep, finalValue))
		}
	}

	return strings.Join(com, endofline) + endofline
}
