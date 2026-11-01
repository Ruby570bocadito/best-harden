package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// compare aplica op a actual y expected. Las comparaciones de texto no
// distinguen mayúsculas; los números se comparan numéricamente aunque
// lleguen como texto ("14" == 14).
func compare(op string, actual, expected any) (bool, error) {
	switch op {
	case "eq":
		return equal(actual, expected), nil
	case "ne":
		return !equal(actual, expected), nil
	case "gt", "gte", "lt", "lte":
		a, okA := toNumber(actual)
		e, okE := toNumber(expected)
		if !okA || !okE {
			return false, fmt.Errorf("%s necesita valores numéricos (actual=%s)", op, formatValue(actual))
		}
		switch op {
		case "gt":
			return a > e, nil
		case "gte":
			return a >= e, nil
		case "lt":
			return a < e, nil
		default:
			return a <= e, nil
		}
	case "between":
		lst := toList(expected)
		if len(lst) != 2 {
			return false, fmt.Errorf("between necesita [mín, máx]")
		}
		a, okA := toNumber(actual)
		lo, ok1 := toNumber(lst[0])
		hi, ok2 := toNumber(lst[1])
		if !okA || !ok1 || !ok2 {
			return false, fmt.Errorf("between necesita valores numéricos (actual=%s)", formatValue(actual))
		}
		return a >= lo && a <= hi, nil
	case "in", "not_in":
		found := false
		for _, e := range toList(expected) {
			if equal(actual, e) {
				found = true
				break
			}
		}
		return found == (op == "in"), nil
	case "contains", "not_contains":
		all := true
		for _, e := range toList(expected) {
			if !containsValue(actual, e) {
				all = false
				break
			}
		}
		if op == "contains" {
			return all, nil
		}
		// not_contains: ninguno de los esperados está presente.
		for _, e := range toList(expected) {
			if containsValue(actual, e) {
				return false, nil
			}
		}
		return true, nil
	case "regex", "not_regex":
		re, err := regexp.Compile(fmt.Sprint(expected))
		if err != nil {
			return false, fmt.Errorf("regex inválida: %w", err)
		}
		m := re.MatchString(formatValue(actual))
		return m == (op == "regex"), nil
	case "bits_set", "bits_clear", "bits_any":
		a, okA := toUint(actual)
		e, okE := toUint(expected)
		if !okA || !okE {
			return false, fmt.Errorf("%s necesita valores enteros (actual=%s)", op, formatValue(actual))
		}
		switch op {
		case "bits_set":
			return a&e == e, nil
		case "bits_clear":
			return a&e == 0, nil
		default:
			return a&e != 0, nil
		}
	case "mode_max":
		a, err1 := parseMode(actual)
		e, err2 := parseMode(expected)
		if err1 != nil || err2 != nil {
			return false, fmt.Errorf("mode_max necesita permisos octales como \"0600\"")
		}
		return a&^e == 0, nil
	}
	return false, fmt.Errorf("operador desconocido %q", op)
}

func equal(a, b any) bool {
	if ab, ok := a.(bool); ok {
		if bb, ok := toBool(b); ok {
			return ab == bb
		}
	}
	if bb, ok := b.(bool); ok {
		if ab, ok := toBool(a); ok {
			return ab == bb
		}
	}
	if an, ok := toNumber(a); ok {
		if bn, ok := toNumber(b); ok {
			return an == bn
		}
	}
	return strings.EqualFold(strings.TrimSpace(formatValue(a)), strings.TrimSpace(formatValue(b)))
}

func containsValue(actual, want any) bool {
	switch v := actual.(type) {
	case []any:
		for _, x := range v {
			if equal(x, want) {
				return true
			}
		}
		return false
	case []string:
		for _, x := range v {
			if equal(x, want) {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(formatValue(actual)), strings.ToLower(formatValue(want)))
}

func toList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case nil:
		return nil
	}
	return []any{v}
}

func toNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		s := strings.TrimSpace(x)
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			n, err := strconv.ParseUint(s[2:], 16, 64)
			return float64(n), err == nil
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
	return 0, false
}

func toUint(v any) (uint64, bool) {
	f, ok := toNumber(v)
	if !ok || f < 0 || f != math.Trunc(f) {
		return 0, false
	}
	return uint64(f), true
}

func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "yes", "on", "enabled":
			return true, true
		case "false", "no", "off", "disabled":
			return false, true
		}
	}
	if n, ok := toNumber(v); ok && (n == 0 || n == 1) {
		return n == 1, true
	}
	return false, false
}

func parseMode(v any) (uint64, error) {
	s := strings.TrimSpace(formatValue(v))
	return strconv.ParseUint(s, 8, 32)
}

// formatValue representa un valor para humanos y para regex.
func formatValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = formatValue(e)
		}
		return strings.Join(parts, ", ")
	case []string:
		return strings.Join(x, ", ")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	}
	return fmt.Sprint(v)
}

// describeExpected explica en español lo que la regla espera.
func describeExpected(op string, expected any) string {
	v := formatValue(expected)
	switch op {
	case "manual":
		return "revisión manual"
	case "eq":
		return v
	case "ne":
		return "≠ " + v
	case "gt":
		return "> " + v
	case "gte":
		return "≥ " + v
	case "lt":
		return "< " + v
	case "lte":
		return "≤ " + v
	case "between":
		l := toList(expected)
		if len(l) == 2 {
			return fmt.Sprintf("entre %s y %s", formatValue(l[0]), formatValue(l[1]))
		}
	case "in":
		return "uno de: " + v
	case "not_in":
		return "ninguno de: " + v
	case "contains":
		return "contiene: " + v
	case "not_contains":
		return "no contiene: " + v
	case "regex":
		return "coincide con /" + v + "/"
	case "not_regex":
		return "no coincide con /" + v + "/"
	case "bits_set":
		return "bits activados: " + hexOf(expected)
	case "bits_clear":
		return "bits desactivados: " + hexOf(expected)
	case "bits_any":
		return "algún bit de: " + hexOf(expected)
	case "mode_max":
		return "permisos ≤ " + v
	case "exists":
		return "presente"
	case "absent":
		return "ausente"
	}
	return op + " " + v
}

func hexOf(v any) string {
	if u, ok := toUint(v); ok {
		return fmt.Sprintf("0x%X", u)
	}
	return formatValue(v)
}

// lookupField resuelve "a.b.c" dentro de mapas anidados. En una lista de
// objetos devuelve el campo de cada uno: "members.Name" son los nombres de
// los miembros.
func lookupField(fields map[string]any, path string) (any, bool) {
	if v, ok := fields[path]; ok {
		return v, true
	}
	var cur any = fields
	for _, part := range strings.Split(path, ".") {
		switch x := cur.(type) {
		case map[string]any:
			v, ok := mapKey(x, part)
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			out := []any{}
			for _, it := range x {
				if m, ok := it.(map[string]any); ok {
					if v, ok := mapKey(m, part); ok {
						out = append(out, v)
					}
				}
			}
			cur = out
		default:
			return nil, false
		}
	}
	return cur, cur != nil
}

// mapKey busca una clave; las de PowerShell pueden variar en mayúsculas.
func mapKey(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}
