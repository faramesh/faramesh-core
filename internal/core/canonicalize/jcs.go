package canonicalize

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// JCSMarshal serializes v to a canonical JSON byte sequence approximating
// RFC 8785 (JCS). This implementation covers common JSON types: objects with
// lexicographically sorted keys, arrays, strings (escaped via json.Marshal),
// booleans, null, and numbers using the shortest decimal representation.
func JCSMarshal(v any) ([]byte, error) {
	var b strings.Builder
	if err := jcsMarshalValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func jcsMarshalValue(sb *strings.Builder, v any) error {
	if v == nil {
		sb.WriteString("null")
		return nil
	}
	switch val := v.(type) {
	case string:
		// use standard json string escaping
		enc, _ := json.Marshal(val)
		sb.Write(enc)
		return nil
	case bool:
		if val {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
		return nil
	case float64:
		sb.WriteString(formatNumber(val))
		return nil
	case float32:
		sb.WriteString(formatNumber(float64(val)))
		return nil
	case int:
		sb.WriteString(strconv.FormatInt(int64(val), 10))
		return nil
	case int64:
		sb.WriteString(strconv.FormatInt(val, 10))
		return nil
	case json.Number:
		// try to preserve integer form if possible
		if i, err := val.Int64(); err == nil {
			sb.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		if f, err := val.Float64(); err == nil {
			sb.WriteString(formatNumber(f))
			return nil
		}
		// fallback to raw string
		sb.WriteString(string(val))
		return nil
	case map[string]any:
		return jcsMarshalObject(sb, val)
	case []any:
		sb.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := jcsMarshalValue(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
		return nil
	default:
		if marshaler, ok := v.(json.Marshaler); ok {
			enc, err := marshaler.MarshalJSON()
			if err != nil {
				return err
			}
			var decoded any
			if err := json.Unmarshal(enc, &decoded); err != nil {
				return err
			}
			return jcsMarshalValue(sb, decoded)
		}
		if tm, ok := v.(time.Time); ok {
			enc, _ := json.Marshal(tm)
			sb.Write(enc)
			return nil
		}
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			sb.WriteString("null")
			return nil
		}
		switch rv.Kind() {
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return errors.New("jcs: only string-keyed maps are supported")
			}
			m := make(map[string]any)
			iter := rv.MapRange()
			for iter.Next() {
				k := iter.Key().String()
				m[k] = iter.Value().Interface()
			}
			return jcsMarshalObject(sb, m)
		case reflect.Struct:
			return jcsMarshalStruct(sb, rv)
		case reflect.Slice, reflect.Array:
			sb.WriteByte('[')
			for i := 0; i < rv.Len(); i++ {
				if i > 0 {
					sb.WriteByte(',')
				}
				if err := jcsMarshalValue(sb, rv.Index(i).Interface()); err != nil {
					return err
				}
			}
			sb.WriteByte(']')
			return nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			sb.WriteString(strconv.FormatInt(rv.Int(), 10))
			return nil
		case reflect.Float32, reflect.Float64:
			sb.WriteString(formatNumber(rv.Float()))
			return nil
		case reflect.Bool:
			if rv.Bool() {
				sb.WriteString("true")
			} else {
				sb.WriteString("false")
			}
			return nil
		case reflect.String:
			enc, _ := json.Marshal(rv.String())
			sb.Write(enc)
			return nil
		default:
			return errors.New("jcs: unsupported type")
		}
	}
}

func jcsMarshalStruct(sb *strings.Builder, rv reflect.Value) error {
	type fieldValue struct {
		name  string
		value any
	}
	fields := make([]fieldValue, 0, rv.NumField())
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		field := rt.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, omitEmpty := jsonFieldName(field)
		if name == "" || name == "-" {
			continue
		}
		fv := rv.Field(i)
		if omitEmpty && isEmptyValue(fv) {
			continue
		}
		fields = append(fields, fieldValue{name: name, value: fv.Interface()})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	sb.WriteByte('{')
	for i, field := range fields {
		if i > 0 {
			sb.WriteByte(',')
		}
		enc, _ := json.Marshal(field.name)
		sb.Write(enc)
		sb.WriteByte(':')
		if err := jcsMarshalValue(sb, field.value); err != nil {
			return err
		}
	}
	sb.WriteByte('}')
	return nil
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name, false
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	omitEmpty := false
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitEmpty = true
		}
	}
	return name, omitEmpty
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	case reflect.Struct:
		if t, ok := v.Interface().(time.Time); ok {
			return t.IsZero()
		}
		return false
	default:
		return false
	}
}

func jcsMarshalObject(sb *strings.Builder, m map[string]any) error {
	sb.WriteByte('{')
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		// marshal key as string
		enc, _ := json.Marshal(k)
		sb.Write(enc)
		sb.WriteByte(':')
		if err := jcsMarshalValue(sb, m[k]); err != nil {
			return err
		}
	}
	sb.WriteByte('}')
	return nil
}

// formatNumber returns a shortest-form decimal representation for f.
// Uses strconv.FormatFloat with 'g' which approximates JCS's shortest representation.
func formatNumber(f float64) string {
	// Handle -0
	if f == 0 {
		return "0"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
