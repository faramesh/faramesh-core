package canonicalize

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
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
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Map:
			// only support map[string]any
			m := make(map[string]any)
			iter := rv.MapRange()
			for iter.Next() {
				k := iter.Key().String()
				m[k] = iter.Value().Interface()
			}
			return jcsMarshalObject(sb, m)
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
			// fallback to standard json.Marshal
			enc, err := json.Marshal(v)
			if err != nil {
				return err
			}
			sb.Write(enc)
			return nil
		}
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
