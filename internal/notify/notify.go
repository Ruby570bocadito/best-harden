// Package notify avisa del resultado del análisis programado: siempre en el
// registro del sistema (el Visor de eventos en Windows, syslog/journald en
// Linux) y, si se configura, en un webhook (ntfy, Slack, Discord, Teams o
// JSON genérico).
//
// El aviso solo lleva el resumen (equipo, puntuaciones y títulos de los
// cambios), nunca evidencias ni configuración.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema identifica el JSON del formato genérico.
const Schema = "adarve.notify/v1"

// Niveles del aviso.
const (
	LevelInfo    = "info"    // ejecución sin cambios a peor
	LevelWarning = "warning" // la postura o la exposición han empeorado
	LevelError   = "error"   // el análisis ha fallado
)

// Formatos de webhook.
const (
	FormatJSON    = "json"
	FormatNtfy    = "ntfy"
	FormatSlack   = "slack"
	FormatDiscord = "discord"
	FormatTeams   = "teams"
)

// Formats son los formatos admitidos.
var Formats = []string{FormatNtfy, FormatSlack, FormatDiscord, FormatTeams, FormatJSON}

// Event es un aviso.
type Event struct {
	Schema       string    `json:"schema"`
	Host         string    `json:"host"`
	Time         time.Time `json:"time"`
	Level        string    `json:"level"`
	Title        string    `json:"title"`
	Lines        []string  `json:"lines"`
	ScanScore    int       `json:"scan_score"`
	SurfaceScore int       `json:"surface_score"`
	Regressions  []string  `json:"regressions,omitempty"`
	NewExposure  []string  `json:"new_exposure,omitempty"`
	Errors       []string  `json:"errors,omitempty"`
	Test         bool      `json:"test,omitempty"`
}

// Text es el aviso en texto: el título y una línea por dato.
func (e Event) Text() string {
	return e.Title + "\n" + strings.Join(e.Lines, "\n")
}

// OneLine es el aviso en una sola línea (syslog).
func (e Event) OneLine() string {
	return e.Title + ": " + strings.Join(e.Lines, " · ")
}

// ValidateURL comprueba la dirección de un webhook: HTTPS, o HTTP solo hacia
// el propio equipo o una dirección privada (un ntfy en casa, por ejemplo),
// para que el aviso no viaje en claro por Internet.
func ValidateURL(raw string) (*url.URL, error) {
	if len(raw) > 2048 {
		return nil, errors.New("la dirección del webhook es demasiado larga")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("la dirección del webhook no es válida: usa https://…")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !(ip.IsLoopback() || ip.IsPrivate())) {
			return nil, fmt.Errorf("el webhook debe usar https:// (http solo se admite hacia este equipo o una IP privada)")
		}
	default:
		return nil, fmt.Errorf("el webhook debe usar https://")
	}
	return u, nil
}

// Redact muestra de un webhook solo el esquema y el servidor: la ruta y la
// consulta suelen llevar el secreto (el tema de ntfy, el token de Slack…).
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(dirección no válida)"
	}
	if u.Path == "" || u.Path == "/" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// FormatFor deduce el formato del servidor del webhook.
func FormatFor(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "hooks.slack.com":
		return FormatSlack
	case (host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com")) && strings.HasPrefix(u.Path, "/api/webhooks/"):
		return FormatDiscord
	case strings.HasSuffix(host, ".webhook.office.com") || strings.HasSuffix(host, ".logic.azure.com") || strings.HasSuffix(host, ".powerplatform.com"):
		return FormatTeams
	case host == "ntfy.sh" || strings.HasPrefix(host, "ntfy."):
		return FormatNtfy
	}
	return FormatJSON
}

// request prepara la petición del webhook en el formato pedido.
func request(ctx context.Context, u *url.URL, format, userAgent string, ev Event) (*http.Request, error) {
	target := *u
	var body any
	switch format {
	case FormatNtfy:
		// Publicación JSON de ntfy: al servidor raíz, con el tema en el
		// cuerpo (los títulos con tildes no viajan bien en cabeceras).
		path := strings.TrimSuffix(u.Path, "/")
		i := strings.LastIndex(path, "/")
		topic := path[i+1:]
		if topic == "" {
			return nil, errors.New("la dirección de ntfy debe terminar en el tema: https://ntfy.sh/<tema>")
		}
		target.Path = path[:i] + "/"
		priority, tag := 3, "white_check_mark"
		switch ev.Level {
		case LevelWarning:
			priority, tag = 4, "warning"
		case LevelError:
			priority, tag = 4, "x"
		}
		body = map[string]any{"topic": topic, "title": ev.Title, "message": strings.Join(ev.Lines, "\n"),
			"priority": priority, "tags": []string{tag, "shield"}}
	case FormatSlack:
		body = map[string]any{"text": "*" + ev.Title + "*\n" + strings.Join(ev.Lines, "\n")}
	case FormatDiscord:
		body = map[string]any{"username": "Adarve", "content": truncate("**"+ev.Title+"**\n"+strings.Join(ev.Lines, "\n"), 1900)}
	case FormatTeams:
		// Tarjeta adaptable: la admiten los flujos de Teams (Workflows) y
		// los conectores de webhook entrante.
		card := map[string]any{"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
			"body": []any{
				map[string]any{"type": "TextBlock", "text": ev.Title, "weight": "Bolder", "size": "Medium", "wrap": true},
				map[string]any{"type": "TextBlock", "text": strings.Join(ev.Lines, "\n\n"), "wrap": true},
			}}
		body = map[string]any{"type": "message", "attachments": []any{
			map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}
	case FormatJSON:
		ev.Schema = Schema
		body = ev
	default:
		return nil, fmt.Errorf("formato de webhook %q desconocido (usa %s)", format, strings.Join(Formats, ", "))
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

// truncate corta s a n bytes como mucho sin partir un carácter.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// client no sigue redirecciones: una redirección convertiría el POST en un
// GET a otro sitio y el aviso se perdería sin error.
var client = &http.Client{
	Timeout:       20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Webhook envía el aviso. format vacío lo deduce de la dirección.
func Webhook(ctx context.Context, raw, format, userAgent string, ev Event) error {
	u, err := ValidateURL(raw)
	if err != nil {
		return err
	}
	if format == "" {
		format = FormatFor(u)
	}
	req, err := request(ctx, u, format, userAgent, ev)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		// El error de net/http incluye la dirección completa, con el secreto.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("no se pudo enviar el aviso a %s: %v", Redact(raw), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		msg := strings.TrimSpace(string(b))
		if msg != "" {
			msg = ": " + msg
		}
		return fmt.Errorf("%s respondió %s%s", Redact(raw), resp.Status, msg)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return nil
}
