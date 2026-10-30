package report

import (
	"io"
	"strings"
	"unicode/utf8"
)

// Cell es una celda de tabla con estilo opcional (color, negrita).
type Cell struct {
	Text  string
	Style func(string) string
}

// Styled crea una celda con estilo.
func Styled(text string, style func(string) string) Cell { return Cell{Text: text, Style: style} }

// Table alinea columnas por su anchura visible. text/tabwriter cuenta los
// códigos de color como caracteres y descuadra las tablas en una terminal
// con colores; aquí el estilo se aplica después de rellenar.
type Table struct {
	Indent string
	rows   [][]Cell
}

// Row añade una fila; cada celda es un string o una Cell.
func (t *Table) Row(cells ...any) {
	row := make([]Cell, len(cells))
	for i, c := range cells {
		switch v := c.(type) {
		case Cell:
			v.Text = Clean(v.Text)
			row[i] = v
		case string:
			row[i] = Cell{Text: Clean(v)}
		}
	}
	t.rows = append(t.rows, row)
}

// Len es el número de filas.
func (t *Table) Len() int { return len(t.rows) }

// Write escribe la tabla con dos espacios entre columnas.
func (t *Table) Write(w io.Writer) {
	var widths []int
	for _, r := range t.rows {
		for i, c := range r {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			if n := utf8.RuneCountInString(c.Text); n > widths[i] {
				widths[i] = n
			}
		}
	}
	var b strings.Builder
	for _, r := range t.rows {
		b.WriteString(t.Indent)
		for i, c := range r {
			text := c.Text
			if c.Style != nil && text != "" {
				text = c.Style(text)
			}
			b.WriteString(text)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c.Text)+2))
			}
		}
		b.WriteString("\n")
	}
	_, _ = io.WriteString(SafeWriter(w), b.String())
}
