// Package compat vigila que los formatos estables de Adarve no cambien sin
// querer (ver docs/16-formatos-y-compatibilidad.md).
//
// Shape describe la forma de un tipo tal como se serializa: un campo por
// línea con su ruta, su tipo y si es opcional. Los tests comparan esa forma
// con un fichero de referencia por formato (testdata/*.txt): quitar,
// renombrar o cambiar el tipo de un campo rompe la compatibilidad y el test
// falla; añadir un campo es compatible, pero también hay que añadirlo a la
// referencia, para que cada cambio de formato sea una decisión explícita.
package compat

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
)

var (
	timeType      = reflect.TypeOf(time.Time{})
	jsonMarshaler = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// Shape devuelve la forma de t serializado con la etiqueta tag ("json" o
// "yaml"), ordenada por ruta.
func Shape(t reflect.Type, tag string) []string {
	var lines []string
	walk(t, "", tag, false, map[reflect.Type]bool{}, &lines)
	sort.Strings(lines)
	return lines
}

func walk(t reflect.Type, path, tag string, optional bool, stack map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	emit := func(kind string) {
		if path == "" {
			return
		}
		if optional {
			kind += " (opcional)"
		}
		*out = append(*out, path+": "+kind)
	}
	// Un tipo que se serializa a su manera: su forma la decide su código.
	if t != timeType && tag == "json" && (t.Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(jsonMarshaler) ||
		t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler)) {
		emit("formato propio (" + t.String() + ")")
		return
	}
	switch {
	case t == timeType:
		emit("fecha RFC 3339")
	case t.Kind() == reflect.String:
		emit(named("texto", t))
	case t.Kind() == reflect.Bool:
		emit("booleano")
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Float64:
		emit(named("número", t))
	case t.Kind() == reflect.Interface:
		emit("cualquiera")
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Array:
		emit("lista")
		walk(t.Elem(), path+"[]", tag, false, stack, out)
	case t.Kind() == reflect.Map:
		emit("objeto")
		walk(t.Elem(), path+".*", tag, false, stack, out)
	case t.Kind() == reflect.Struct:
		if stack[t] {
			emit("objeto (recursivo: " + t.String() + ")")
			return
		}
		emit("objeto")
		stack[t] = true
		fields(t, path, tag, stack, out)
		delete(stack, t)
	default:
		emit("?" + t.Kind().String())
	}
}

// fields recorre los campos serializables de una estructura.
func fields(t reflect.Type, path, tag string, stack map[reflect.Type]bool, out *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous { // sin exportar
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get(tag), ",")
		if name == "-" && opts == "" {
			continue
		}
		inline := f.Anonymous && name == "" && (tag == "json" || strings.Contains(opts, "inline"))
		if tag == "yaml" && strings.Contains(opts, "inline") {
			inline = true
		}
		if inline {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				fields(ft, path, tag, stack, out)
				continue
			}
		}
		if f.PkgPath != "" { // embebido sin exportar y sin aplanar
			continue
		}
		if name == "" {
			name = f.Name
			if tag == "yaml" { // yaml.v3: el nombre del campo en minúsculas
				name = strings.ToLower(name)
			}
		}
		key := name
		if path != "" {
			key = path + "." + name
		}
		walk(f.Type, key, tag, strings.Contains(opts, "omitempty"), stack, out)
	}
}

// named añade el tipo con nombre (p. ej. engine.Status) a un tipo básico:
// sus valores posibles están en ese tipo.
func named(base string, t reflect.Type) string {
	if t.PkgPath() == "" || t.Name() == "" {
		return base
	}
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if !unicode.IsUpper(rune(t.Name()[0])) {
		return base
	}
	return fmt.Sprintf("%s (%s.%s)", base, pkg, t.Name())
}
