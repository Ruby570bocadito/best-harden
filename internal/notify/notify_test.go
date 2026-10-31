package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func sample() Event {
	return Event{Host: "Rby", Time: time.Date(2026, 10, 17, 7, 0, 0, 0, time.UTC), Level: LevelWarning,
		Title:     "Adarve · Rby: la postura o la exposición han empeorado",
		Lines:     []string{"Postura 78/100 · exposición 53/100", "Cambios que aumentan la exposición (1):", "· 8766/tcp (AutoClaw.exe) escucha en la red: abierto a cualquiera"},
		ScanScore: 78, SurfaceScore: 53, NewExposure: []string{"8766/tcp (AutoClaw.exe) escucha en la red: abierto a cualquiera"}}
}

func TestValidateURL(t *testing.T) {
	for _, ok := range []string{"https://ntfy.sh/adarve-rby-1234", "https://hooks.slack.com/services/T/B/X", "http://127.0.0.1:8080/x",
		"http://192.168.1.10/ntfy/topic", "http://localhost/hook"} {
		if _, err := ValidateURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://ntfy.sh/topic", "http://8.8.8.8/x", "ftp://x/y", "ntfy.sh/topic", "https://", "file:///etc/passwd",
		"https://x/" + strings.Repeat("a", 3000)} {
		if _, err := ValidateURL(bad); err == nil {
			t.Errorf("%s debería rechazarse", bad)
		}
	}
}

func TestRedactAndFormat(t *testing.T) {
	if got := Redact("https://user:pass@ntfy.sh/secreto?auth=tok"); got != "https://ntfy.sh/…" {
		t.Errorf("Redact: %s", got)
	}
	cases := map[string]string{
		"https://hooks.slack.com/services/T/B/X":                         FormatSlack,
		"https://discord.com/api/webhooks/1/abc":                         FormatDiscord,
		"https://ptb.discord.com/api/webhooks/1/abc":                     FormatDiscord,
		"https://discord.com/channels/1":                                 FormatJSON,
		"https://contoso.webhook.office.com/webhookb2/x":                 FormatTeams,
		"https://prod-12.westeurope.logic.azure.com:443/workflows/x":     FormatTeams,
		"https://ntfy.sh/adarve-rby":                                     FormatNtfy,
		"https://ntfy.example.org/alerts":                                FormatNtfy,
		"https://example.org/hooks/adarve":                               FormatJSON,
		"https://default123.environment.api.powerplatform.com/workflows": FormatTeams,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := FormatFor(u); got != want {
			t.Errorf("%s: %s, quiero %s", raw, got, want)
		}
	}
}

// capture levanta un servidor que guarda la última petición.
func capture(t *testing.T, status int) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var last http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = *r
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("respuesta del servidor"))
	}))
	t.Cleanup(srv.Close)
	return srv, &last, &body
}

func TestWebhookFormats(t *testing.T) {
	ev := sample()
	srv, last, body := capture(t, http.StatusOK)

	// ntfy: publicación JSON al servidor raíz con el tema en el cuerpo.
	if err := Webhook(context.Background(), srv.URL+"/ntfy/adarve-rby", FormatNtfy, "adarve/test", ev); err != nil {
		t.Fatal(err)
	}
	var n struct {
		Topic, Title, Message string
		Priority              int
		Tags                  []string
	}
	if err := json.Unmarshal(*body, &n); err != nil || last.URL.Path != "/ntfy/" || n.Topic != "adarve-rby" || n.Title != ev.Title ||
		n.Priority != 4 || n.Tags[0] != "warning" || !strings.Contains(n.Message, "AutoClaw") {
		t.Errorf("ntfy: %s %s %+v", last.URL.Path, *body, n)
	}
	if last.Header.Get("User-Agent") != "adarve/test" || last.Method != http.MethodPost {
		t.Errorf("cabeceras: %s %v", last.Method, last.Header)
	}
	if err := Webhook(context.Background(), srv.URL+"/", FormatNtfy, "ua", ev); err == nil {
		t.Error("ntfy sin tema debería fallar")
	}

	// Slack y Discord: texto con el título en negrita.
	if err := Webhook(context.Background(), srv.URL+"/slack", FormatSlack, "ua", ev); err != nil {
		t.Fatal(err)
	}
	var s struct{ Text string }
	if json.Unmarshal(*body, &s); !strings.HasPrefix(s.Text, "*Adarve · Rby") {
		t.Errorf("slack: %s", *body)
	}
	long := ev
	long.Lines = []string{strings.Repeat("ñ", 2000)}
	if err := Webhook(context.Background(), srv.URL+"/discord", FormatDiscord, "ua", long); err != nil {
		t.Fatal(err)
	}
	var d struct{ Content string }
	if json.Unmarshal(*body, &d); len(d.Content) > 1910 || !strings.HasSuffix(d.Content, "ñ…") {
		t.Errorf("discord: %d bytes, %q", len(d.Content), d.Content[len(d.Content)-10:])
	}

	// Teams: tarjeta adaptable.
	if err := Webhook(context.Background(), srv.URL+"/teams", FormatTeams, "ua", ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(*body), `"contentType":"application/vnd.microsoft.card.adaptive"`) || !strings.Contains(string(*body), "AdaptiveCard") {
		t.Errorf("teams: %s", *body)
	}

	// JSON genérico: el evento con su esquema.
	if err := Webhook(context.Background(), srv.URL+"/json", "", "ua", ev); err != nil {
		t.Fatal(err)
	}
	var j Event
	if err := json.Unmarshal(*body, &j); err != nil || j.Schema != Schema || j.Host != "Rby" || j.SurfaceScore != 53 || len(j.NewExposure) != 1 {
		t.Errorf("json: %s", *body)
	}
	if err := Webhook(context.Background(), srv.URL+"/x", "telegram", "ua", ev); err == nil || !strings.Contains(err.Error(), "desconocido") {
		t.Errorf("formato desconocido: %v", err)
	}
}

func TestWebhookErrorsHideSecret(t *testing.T) {
	ev := sample()
	srv, _, _ := capture(t, http.StatusNotFound)
	err := Webhook(context.Background(), srv.URL+"/tema-secreto", FormatNtfy, "ua", ev)
	if err == nil || strings.Contains(err.Error(), "tema-secreto") || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "respuesta del servidor") {
		t.Errorf("error HTTP: %v", err)
	}
	// Sin servidor: el error de red tampoco lleva la ruta.
	srv.Close()
	err = Webhook(context.Background(), srv.URL+"/tema-secreto", FormatNtfy, "ua", ev)
	if err == nil || strings.Contains(err.Error(), "tema-secreto") {
		t.Errorf("error de red: %v", err)
	}
}

func TestWebhookNoRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	if err := Webhook(context.Background(), redirect.URL+"/hook", FormatJSON, "ua", sample()); err == nil || hits != 0 {
		t.Errorf("una redirección es un error y no se sigue: %v (%d)", err, hits)
	}
}

func TestTextAndOneLine(t *testing.T) {
	ev := sample()
	if !strings.HasPrefix(ev.Text(), ev.Title+"\nPostura 78/100") || strings.Contains(ev.OneLine(), "\n") {
		t.Errorf("texto: %q / %q", ev.Text(), ev.OneLine())
	}
}
