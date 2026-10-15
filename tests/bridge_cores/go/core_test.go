// Tests of the vendored Go bridge core against the contract's vectors (hub/subsidiary/contract/vectors.json, path in
// ATRIUM_VECTORS) and the panel, on-behalf-of, grant and events behaviour. Copied next to core.go by
// tests/bridge_cores/test_go_core.py; no network beyond 127.0.0.1 (httptest).
package atriumbridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type step struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	BodyB64 string            `json:"body_b64"`
	Expect  struct {
		Status int            `json:"status"`
		Code   string         `json:"code"`
		JSON   map[string]any `json:"json"`
		SHA256 string         `json:"sha256"`
	} `json:"expect"`
}

type tokenUnits struct {
	Keys  string `json:"keys"`
	Tool  string `json:"tool"`
	Sub   string `json:"sub"`
	Now   int64  `json:"now"`
	Cases []struct {
		Title   string          `json:"title"`
		Token   string          `json:"token"`
		Action  string          `json:"action"`
		BodyB64 string          `json:"body_b64"`
		OK      bool            `json:"ok"`
		Payload json.RawMessage `json:"payload"`
		Code    string          `json:"code"`
	} `json:"cases"`
}

type vectorsFile struct {
	Now         int64 `json:"now"`
	Conformance struct {
		Env         map[string]string `json:"env"`
		ManifestB64 string            `json:"manifest_b64"`
		PanelB64    string            `json:"panel_js_b64"`
		PanelSHA    string            `json:"panel_sha256"`
		Vectors     []struct {
			ID    string `json:"id"`
			Steps []step `json:"steps"`
		} `json:"vectors"`
	} `json:"conformance"`
	Units struct {
		B64u []struct {
			In  string `json:"in"`
			OK  bool   `json:"ok"`
			Hex string `json:"hex"`
		} `json:"b64u"`
		Keys []struct {
			Value string `json:"value"`
			OK    bool   `json:"ok"`
			Count int    `json:"count"`
		} `json:"keys"`
		Tickets tokenUnits `json:"tickets"`
		Grants  tokenUnits `json:"grants"`
		Signing []struct {
			Title      string  `json:"title"`
			Method     string  `json:"method"`
			Path       string  `json:"path"`
			Date       string  `json:"date"`
			Nonce      string  `json:"nonce"`
			BodyB64    string  `json:"body_b64"`
			BodySHA    string  `json:"body_sha256"`
			TicketJTI  string  `json:"ticket_jti"`
			GrantJTI   *string `json:"grant_jti"`
			OnBehalfOf *string `json:"on_behalf_of"`
			String     string  `json:"string"`
			Cnf        string  `json:"cnf"`
			Signature  string  `json:"signature"`
			Valid      bool    `json:"valid"`
		} `json:"signing"`
		Params struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
			Cases   []struct {
				Title   string          `json:"title"`
				Schema  string          `json:"schema"`
				BodyB64 string          `json:"body_b64"`
				OK      bool            `json:"ok"`
				Params  json.RawMessage `json:"params"`
			} `json:"cases"`
		} `json:"params"`
	} `json:"units"`
}

func load(t *testing.T) vectorsFile {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("ATRIUM_VECTORS"))
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	return v
}

func std(t *testing.T, text string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return data
}

// wire decodes a conformance step's body: base64url without padding, as on the wire.
func wire(t *testing.T, text string) []byte {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("base64url: %v", err)
	}
	return data
}

func code(err error) string {
	if r, ok := err.(*Refusal); ok {
		return r.Code
	}
	if err != nil {
		return "error"
	}
	return ""
}

func same(t *testing.T, got any, want json.RawMessage) bool {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var a, b any
	_ = json.Unmarshal(raw, &a)
	_ = json.Unmarshal(want, &b)
	return reflect.DeepEqual(a, b)
}

func TestUnitVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Units.B64u {
		data, err := B64uDecode(c.In)
		if (err == nil) != c.OK || (c.OK && hex.EncodeToString(data) != c.Hex) {
			t.Errorf("b64u %q: %v %x", c.In, err, data)
		}
	}
	for _, c := range v.Units.Keys {
		keys, err := ParseKeys(c.Value)
		if (err == nil) != c.OK || (c.OK && len(keys) != c.Count) {
			t.Errorf("keys %q: %v", c.Value, err)
		}
	}
	for _, units := range []struct {
		name, prefix, code string
		u                  tokenUnits
	}{{"ticket", "AT1", "bad_ticket", v.Units.Tickets}, {"grant", "AG1", "grant_mismatch", v.Units.Grants}} {
		keys, err := ParseKeys(units.u.Keys)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range units.u.Cases {
			p, err := VerifyToken(c.Token, units.prefix, keys, units.code)
			if err == nil && units.name == "ticket" {
				if !TicketFieldsOK(p) {
					err = refuse("bad_ticket")
				} else {
					err = CheckTicket(p, units.u.Tool, units.u.Sub, units.u.Now)
				}
			}
			if err == nil && units.name == "grant" {
				if !GrantFieldsOK(p) {
					err = refuse("grant_mismatch")
				} else {
					err = CheckGrant(p, units.u.Tool, units.u.Sub, c.Action, std(t, c.BodyB64), units.u.Now)
				}
			}
			if c.OK && (err != nil || !same(t, p, c.Payload)) {
				t.Errorf("%s %q: %v", units.name, c.Title, err)
			}
			if !c.OK && code(err) != c.Code {
				t.Errorf("%s %q: got %q, want %q", units.name, c.Title, code(err), c.Code)
			}
		}
	}
	for _, c := range v.Units.Signing {
		grant, obo := "", ""
		if c.GrantJTI != nil {
			grant = *c.GrantJTI
		}
		if c.OnBehalfOf != nil {
			obo = *c.OnBehalfOf
		}
		body := std(t, c.BodyB64)
		message := SigningString(c.Method, c.Path, c.Date, c.Nonce, body, c.TicketJTI, grant, obo)
		sum := sha256.Sum256(body)
		if c.Valid && (string(message) != c.String || hex.EncodeToString(sum[:]) != c.BodySHA) {
			t.Errorf("signing %q: %q", c.Title, message)
		}
		if VerifySignature(c.Cnf, c.Signature, message) != c.Valid {
			t.Errorf("signing %q: verification is not %v", c.Title, c.Valid)
		}
	}
	for _, c := range v.Units.Params.Cases {
		params, err := ValidateBody(v.Units.Params.Schemas[c.Schema], std(t, c.BodyB64))
		if c.OK && (err != nil || !same(t, params, c.Params)) {
			t.Errorf("params %q: %v %v", c.Title, err, params)
		}
		if !c.OK && code(err) != "bad_params" {
			t.Errorf("params %q: got %q", c.Title, code(err))
		}
	}
}

func dig(value any, dotted string) (any, bool) {
	for _, part := range strings.Split(dotted, ".") {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		if value, ok = m[part]; !ok {
			return nil, false
		}
	}
	return value, true
}

func send(t *testing.T, server *httptest.Server, s step, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(s.Method, server.URL+s.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func check(s step, status int, body []byte) string {
	if status != s.Expect.Status {
		return "status " + strconv.Itoa(status) + ", expected " + strconv.Itoa(s.Expect.Status) + ": " + string(body)
	}
	if s.Expect.SHA256 != "" {
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != s.Expect.SHA256 {
			return "the body's SHA-256 differs"
		}
	}
	if s.Expect.Code == "" && s.Expect.JSON == nil {
		return ""
	}
	var data any
	if json.Unmarshal(body, &data) != nil {
		return "not JSON"
	}
	if s.Expect.Code != "" {
		if got, _ := dig(data, "code"); got != s.Expect.Code {
			return "code " + string(body)
		}
	}
	for dotted, want := range s.Expect.JSON {
		if got, _ := dig(data, dotted); !reflect.DeepEqual(got, want) {
			return dotted + " differs: " + string(body)
		}
	}
	return ""
}

func conformanceBridge(t *testing.T, v vectorsFile) *Bridge {
	t.Helper()
	manifest := std(t, v.Conformance.ManifestB64)
	var m struct {
		Actions []struct {
			ID string `json:"id"`
		} `json:"actions"`
	}
	_ = json.Unmarshal(manifest, &m)
	actions := map[string]Handler{}
	for _, a := range m.Actions {
		actions[a.ID] = func(params map[string]any, ctx *Ctx) (any, error) { return map[string]any{"ok": true}, nil }
	}
	env := v.Conformance.Env
	b := New(Glue{Actions: actions, Manifest: manifest, PanelJS: std(t, v.Conformance.PanelB64),
		PanelSHA256: v.Conformance.PanelSHA, Env: func(k string) string { return env[k] },
		Clock: func() time.Time { return time.Unix(v.Now, 0) }})
	if !b.Ready() {
		t.Fatalf("not ready: %s", b.Problem())
	}
	return b
}

func TestConformanceVectors(t *testing.T) {
	v := load(t)
	server := httptest.NewServer(conformanceBridge(t, v))
	defer server.Close()
	for _, vector := range v.Conformance.Vectors {
		for i, s := range vector.Steps {
			status, body := send(t, server, s, wire(t, s.BodyB64))
			if problem := check(s, status, body); problem != "" {
				t.Errorf("%s step %d: %s", vector.ID, i+1, problem)
			}
		}
	}
}

func TestFailsClosedWithoutKeys(t *testing.T) {
	v := load(t)
	b := New(Glue{Manifest: std(t, v.Conformance.ManifestB64), Env: func(string) string { return "" }})
	server := httptest.NewServer(b)
	defer server.Close()
	for path, want := range map[string]int{"/.atrium/v1/health": 200, "/.atrium/panel.js": 503,
		"/.atrium/v1/panel/status": 503} {
		if status, _ := send(t, server, step{Method: "GET", Path: path}, nil); status != want {
			t.Errorf("%s: %d", path, status)
		}
	}
	if status, body := send(t, server, step{Method: "POST", Path: "/.atrium/v1/call/atrium.ping"}, []byte(`{"params":{}}`)); status != 503 || !strings.Contains(string(body), "not_configured") {
		t.Errorf("call: %d %s", status, body)
	}
}

// ---- a scripted Atrium and sidecar for the stateful behaviour ----

type harness struct {
	t      *testing.T
	key    ed25519.PrivateKey
	probe  ed25519.PrivateKey
	now    int64
	server *httptest.Server
	bridge *Bridge
	n      int
}

const subID = "sub_0123456789ab"

var testManifest = []byte(`{"contract": "atrium-bridge/1", "tool_id": "helpdesk", "stack": "go-nethttp", "core": "go/1.0.0",
 "panel": {"enabled": true}, "events": {"names": ["helpdesk.ticket.updated"]}, "files": ["atrium-bridge.json"],
 "actions": [
  {"id": "tickets.list", "title": "List tickets", "risk": "read", "on_behalf_of": true,
   "params": {"type": "object", "additionalProperties": false, "properties": {}}},
  {"id": "tickets.set_priority", "title": "Set a priority", "risk": "write", "reversible": true,
   "params": {"type": "object", "additionalProperties": false, "required": ["ticket_id", "priority"],
              "properties": {"ticket_id": {"type": "integer"}, "priority": {"enum": ["low", "high"]}}}}]}`)

func newHarness(t *testing.T, grants GrantStore, allow string) *harness {
	seed := bytes.Repeat([]byte{7}, 32)
	h := &harness{t: t, key: ed25519.NewKeyFromSeed(seed), probe: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)),
		now: 1800000000}
	env := map[string]string{"ATRIUM_BRIDGE_KEYS": b64u(h.key.Public().(ed25519.PublicKey)), "ATRIUM_TOOL_ID": "helpdesk",
		"ATRIUM_SUBSIDIARY_ID": subID, "ATRIUM_BRIDGE_ALLOW": allow}
	sum := sha256.Sum256(vendoredPanel)
	h.bridge = New(Glue{Manifest: testManifest, PanelSHA256: hex.EncodeToString(sum[:]), Grants: grants,
		Env: func(k string) string { return env[k] }, Clock: func() time.Time { return time.Unix(h.now, 0) },
		CurrentUser: func(r *http.Request) *User {
			if id := r.Header.Get("X-Test-User"); id != "" {
				return &User{ID: id, Display: "User " + id, Roles: []string{"agent"}}
			}
			return nil
		},
		Actions: map[string]Handler{
			"tickets.list": func(params map[string]any, ctx *Ctx) (any, error) {
				who := ""
				if ctx.User != nil {
					who = ctx.User.ID
				}
				return map[string]any{"as": ctx.Principal, "for": who}, nil
			},
			"tickets.set_priority": func(params map[string]any, ctx *Ctx) (any, error) {
				ctx.Emit("helpdesk.ticket.updated", map[string]any{"id": params["ticket_id"]})
				return map[string]any{"priority": params["priority"]}, nil
			},
		}})
	if !h.bridge.Ready() {
		t.Fatalf("not ready: %s", h.bridge.Problem())
	}
	h.server = httptest.NewServer(h.bridge)
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) token(prefix string, payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	signed := prefix + "." + b64u(raw)
	return signed + "." + b64u(ed25519.Sign(h.key, []byte(signed)))
}

func (h *harness) ticket() (string, string) {
	h.n++
	jti := "ticket-" + strconv.Itoa(h.n)
	return h.token("AT1", map[string]any{"v": 1, "typ": "ticket", "sub": subID, "tool": "helpdesk", "cv": 1,
		"mode": "active", "act": []string{"atrium.ping", "atrium.receipt", "atrium.panel.pull", "atrium.panel.answer",
			"atrium.events.pull", "tickets.list", "tickets.set_priority"},
		"cnf": b64u(h.probe.Public().(ed25519.PublicKey)), "rl": map[string]int{"calls_per_min": 100, "panel_per_user_hour": 2},
		"iat": h.now, "exp": h.now + 600, "jti": jti}), jti
}

func (h *harness) call(action string, params map[string]any, grant, grantJTI, obo string) (int, map[string]any) {
	ticket, jti := h.ticket()
	body, _ := json.Marshal(map[string]any{"params": params})
	h.n++
	nonce := b64u([]byte("nonce-number-" + strconv.Itoa(1000+h.n)))
	date := strconv.FormatInt(h.now, 10)
	path := "/.atrium/v1/call/" + action
	headers := map[string]string{"Atrium-Ticket": ticket, "Atrium-Date": date, "Atrium-Nonce": nonce,
		"Atrium-Signature": b64u(ed25519.Sign(h.probe, SigningString("POST", path, date, nonce, body, jti, grantJTI, obo)))}
	if grant != "" {
		headers["Atrium-Grant"] = grant
	}
	if obo != "" {
		headers["Atrium-On-Behalf-Of"] = obo
	}
	status, raw := send(h.t, h.server, step{Method: "POST", Path: path, Headers: headers}, body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out
}

func (h *harness) grant(action string, params map[string]any, jti string) string {
	body, _ := json.Marshal(map[string]any{"params": params})
	return h.token("AG1", map[string]any{"v": 1, "typ": "grant", "sub": subID, "tool": "helpdesk", "cv": 1,
		"act": action, "bh": BodyHash(body), "apv": "ap_1", "iat": h.now, "exp": h.now + 600, "jti": jti})
}

func (h *harness) panel(method, path, user string, body string, header bool) (int, map[string]any) {
	headers := map[string]string{}
	if header {
		headers["X-Atrium-Panel"] = "1"
	}
	if user != "" {
		headers["X-Test-User"] = user
	}
	status, raw := send(h.t, h.server, step{Method: method, Path: path, Headers: headers}, []byte(body))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out
}

func TestPanelOnBehalfOfAndAnswers(t *testing.T) {
	h := newHarness(t, nil, "")
	if status, _ := h.panel("POST", "/.atrium/v1/panel/ask", "u1", `{"text":"hi"}`, false); status != 403 {
		t.Fatalf("no header: %d", status)
	}
	if status, _ := h.panel("POST", "/.atrium/v1/panel/ask", "", `{"text":"hi"}`, true); status != 401 {
		t.Fatalf("no session: %d", status)
	}
	if status, out := h.panel("GET", "/.atrium/v1/panel/status", "u1", "", true); status != 200 || out["enabled"] != true || out["team_online"] != false {
		t.Fatalf("status: %d %v", status, out)
	}
	status, out := h.panel("POST", "/.atrium/v1/panel/ask", "u1", `{"text":"why is 42 open?","page":{"path":"/t/42","record_id":"ticket:42"}}`, true)
	qid, _ := out["question_id"].(string)
	if status != 200 || !strings.HasPrefix(qid, "q_") {
		t.Fatalf("ask: %d %v", status, out)
	}
	if status, _ := h.panel("POST", "/.atrium/v1/panel/ask", "u1", `{"text":"x","extra":1}`, true); status != 422 {
		t.Fatalf("extra field: %d", status)
	}
	if status, _ := h.panel("GET", "/.atrium/v1/panel/questions/"+qid, "u2", "", true); status != 404 {
		t.Fatalf("another user read the question: %d", status)
	}
	status, out = h.call("atrium.panel.pull", map[string]any{}, "", "", "")
	pulled, _ := out["result"].([]any)
	if status != 200 || len(pulled) != 1 {
		t.Fatalf("pull: %d %v", status, out)
	}
	first := pulled[0].(map[string]any)
	if first["id"] != qid || first["tool_user"].(map[string]any)["id"] != "u1" {
		t.Fatalf("pulled: %v", first)
	}
	if status, out = h.call("tickets.list", map[string]any{}, "", "", qid); status != 200 || out["result"].(map[string]any)["for"] != "u1" {
		t.Fatalf("on behalf: %d %v", status, out)
	}
	if status, out = h.call("tickets.list", map[string]any{}, "", "", "q_unknown"); status != 403 || out["code"] != "forbidden_on_behalf" {
		t.Fatalf("unknown question: %d %v", status, out)
	}
	params := map[string]any{"ticket_id": 42, "priority": "high"}
	if status, out = h.call("tickets.set_priority", params, h.grant("tickets.set_priority", params, "g-obo"), "g-obo", qid); status != 403 || out["code"] != "forbidden_on_behalf" {
		t.Fatalf("a write on behalf: %d %v", status, out)
	}
	answer := "<script>alert(1)</script>\nplain text"
	if status, out = h.call("atrium.panel.answer", map[string]any{"question_id": qid, "text": answer, "status": "answered", "by": "desk"}, "", "", ""); status != 200 || out["result"].(map[string]any)["ok"] != true {
		t.Fatalf("answer: %d %v", status, out)
	}
	status, out = h.panel("GET", "/.atrium/v1/panel/questions/"+qid, "u1", "", true)
	if status != 200 || out["status"] != "answered" || out["answer"] != answer || out["by"] != "desk" {
		t.Fatalf("question: %d %v", status, out)
	}
	if status, out = h.call("tickets.list", map[string]any{}, "", "", qid); status != 403 {
		t.Fatalf("an answered question still acts: %d %v", status, out)
	}
	_, _ = h.panel("POST", "/.atrium/v1/panel/ask", "u1", `{"text":"two"}`, true)
	if status, out = h.panel("POST", "/.atrium/v1/panel/ask", "u1", `{"text":"three"}`, true); status != 429 {
		t.Fatalf("per-user limit: %d %v", status, out)
	}
	h.now += 121 // no pull for two minutes: the open question is answered "unavailable"
	status, out = h.panel("GET", "/.atrium/v1/panel/status", "u1", "", true)
	if out["team_online"] != false {
		t.Fatalf("online after two minutes: %v", out)
	}
}

func TestGrantSingleUseAcrossRestartsAndEvents(t *testing.T) {
	file := filepath.Join(t.TempDir(), "grants.json")
	h := newHarness(t, NewFileGrants(file), "")
	params := map[string]any{"ticket_id": 7, "priority": "low"}
	if status, out := h.call("tickets.set_priority", params, "", "", ""); status != 403 || out["code"] != "grant_required" {
		t.Fatalf("no grant: %d %v", status, out)
	}
	grant := h.grant("tickets.set_priority", params, "g-1")
	status, out := h.call("tickets.set_priority", params, grant, "g-1", "")
	if status != 200 || out["receipt"].(map[string]any)["status"] != "executed" {
		t.Fatalf("granted: %d %v", status, out)
	}
	if status, out = h.call("tickets.set_priority", map[string]any{"ticket_id": 8, "priority": "low"}, grant, "g-1", ""); status != 403 {
		t.Fatalf("another body: %d %v", status, out)
	}
	if status, out = h.call("atrium.events.pull", map[string]any{"after": 0}, "", "", ""); status != 200 {
		t.Fatalf("events: %d %v", status, out)
	}
	events := out["result"].(map[string]any)["events"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["cause"].(map[string]any)["jti"] != "g-1" {
		t.Fatalf("events: %v", events)
	}
	if !h.bridge.Emit("helpdesk.ticket.updated", nil) || h.bridge.Emit("helpdesk.undeclared", nil) {
		t.Fatal("emit")
	}
	// a restart with the same store refuses the used grant and reports its receipt
	h2 := newHarness(t, NewFileGrants(file), "")
	if status, out = h2.call("tickets.set_priority", params, grant, "g-1", ""); status != 409 || out["code"] != "grant_used" {
		t.Fatalf("after a restart: %d %v", status, out)
	}
	if status, out = h2.call("atrium.receipt", map[string]any{"jti": "g-1"}, "", "", ""); out["result"].(map[string]any)["status"] != "executed" {
		t.Fatalf("receipt: %d %v", status, out)
	}
	if status, out = h2.call("atrium.receipt", map[string]any{"jti": "g-2"}, "", "", ""); out["result"].(map[string]any)["status"] != "unused" {
		t.Fatalf("unused receipt: %d %v", status, out)
	}
}

type racingGrants struct{ *MemoryGrants }

func (racingGrants) Used(string) bool { return false } // every racing call passes Used; only one can Mark

func TestMarkIsTheAuthoritativeSingleUseCheck(t *testing.T) {
	h := newHarness(t, racingGrants{NewMemoryGrants()}, "")
	params := map[string]any{"ticket_id": 3, "priority": "high"}
	grant := h.grant("tickets.set_priority", params, "g-race")
	if status, _ := h.call("tickets.set_priority", params, grant, "g-race", ""); status != 200 {
		t.Fatalf("first: %d", status)
	}
	if status, out := h.call("tickets.set_priority", params, grant, "g-race", ""); status != 409 || out["code"] != "grant_used" {
		t.Fatalf("second: %d %v", status, out)
	}
	n := NewMemoryNonces()
	if n.Add("a", 1) != nil || code(n.Add("a", 2)) != "replay" || n.Add("a", 1+nonceTTL) != nil {
		t.Fatal("nonce store")
	}
}

func TestSourceAllowList(t *testing.T) {
	if status, out := newHarness(t, nil, "10.0.0.0/8").call("atrium.ping", map[string]any{}, "", "", ""); status != 403 || out["code"] != "source_not_allowed" {
		t.Fatalf("outside the allow list: %d %v", status, out)
	}
	if status, _ := newHarness(t, nil, "127.0.0.0/8, ::1/128").call("atrium.ping", map[string]any{}, "", "", ""); status != 200 {
		t.Fatalf("inside the allow list: %d", status)
	}
}

func TestPanelScriptIsTheVendoredWidget(t *testing.T) {
	h := newHarness(t, nil, "")
	res, err := http.Get(h.server.URL + "/.atrium/panel.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	sum := sha256.Sum256(body)
	if res.StatusCode != 200 || !bytes.Equal(body, vendoredPanel) || res.Header.Get("ETag") != `"`+hex.EncodeToString(sum[:])+`"` ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "application/javascript") {
		t.Fatalf("panel.js: %d %v", res.StatusCode, res.Header)
	}
}
