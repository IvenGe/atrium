// Package atriumbridge is the Atrium bridge core for Go >= 1.20 - contract atrium-bridge/1 (Atrium's
// docs/SUBSIDIARIES.md has the full text).
//
// VENDORED FILE: Atrium adds it byte-identical (with panel.js next to it) and checks its SHA-256; do not edit it.
// Everything tool-specific lives in the glue: the action handlers, the current-user hook and the service principal.
// Standard library only.
//
// The bridge lets an agent team that runs in a sidecar next to this tool work inside it while Atrium keeps every
// decision. It holds NO secret: it verifies Atrium's Ed25519 signatures with the public keys in ATRIUM_BRIDGE_KEYS.
// Every sidecar call carries a short-lived ticket, a signature made with the sidecar's own key and, for changes, a
// single-use grant Atrium signs after a person approved the exact request.
//
//	bridge := atriumbridge.New(atriumbridge.Glue{Actions: ..., CurrentUser: ..., ServicePrincipal: "atrium-team"})
//	mux.Handle("/.atrium/", bridge)          // behind the session middleware that identifies the user
//	atriumbridge.EmitContext(ctx, "helpdesk.ticket.created", map[string]any{"id": 42})
package atriumbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	Contract      = "atrium-bridge/1"
	CoreVersion   = "go/1.0.0"
	PanelJSSHA256 = "169f62fab9b60d01232e02f5f4feb89e81172819c5fe0e3a4042e6a88ef03898"

	healthPath          = "/.atrium/v1/health"
	callPrefix          = "/.atrium/v1/call/"
	panelJSPath         = "/.atrium/panel.js"
	panelAskPath        = "/.atrium/v1/panel/ask"
	panelQuestionPrefix = "/.atrium/v1/panel/questions/"
	panelStatusPath     = "/.atrium/v1/panel/status"

	clockLeeway        = 60
	nonceTTL           = 180
	nonceCapacity      = 10000
	grantJTIKeep       = 3600
	maxTokenPayload    = 4096
	maxToken           = 6144
	maxKeys            = 2
	MaxBody            = 64 * 1024
	MaxResponse        = 1024 * 1024
	maxActions         = 40
	maxProperties      = 20
	maxString          = 10000
	maxItems           = 100
	maxEnum            = 100
	maxSafeInt         = 1<<53 - 1
	waitMax            = 25
	panelTextMax       = 2000
	panelOpenMax       = 200
	panelExpiry        = 30 * 60
	panelOnlineWindow  = 60
	panelOfflineAnswer = 120
	panelPullMax       = 20
	panelUnavailable   = "The team is not available right now"
	outboxMax          = 1000
	outboxTTL          = 24 * 3600
	eventPayloadMax    = 16 * 1024
	eventsPullMax      = 100
)

//go:embed panel.js
var vendoredPanel []byte

var (
	statuses = map[string]int{
		"bad_ticket": 401, "bad_signature": 401, "expired": 401, "replay": 401,
		"action_not_allowed": 403, "probation": 403, "grant_required": 403, "grant_mismatch": 403,
		"forbidden_on_behalf": 403, "source_not_allowed": 403,
		"grant_used": 409, "too_large": 413, "bad_params": 422, "rate_limited": 429,
		"not_configured": 503, "busy": 503,
		"no_session": 401, "panel_header_required": 403, "not_found": 404,
	}
	defaultRate       = map[string]int64{"calls_per_min": 30, "panel_per_user_hour": 10}
	probationBuiltins = []string{"atrium.ping", "atrium.describe", "atrium.noop_write", "atrium.receipt"}
	builtinsJSON      = `{
 "atrium.ping": {"risk": "read", "params": {"type": "object", "additionalProperties": false, "properties": {}, "required": []}},
 "atrium.describe": {"risk": "read", "params": {"type": "object", "additionalProperties": false, "properties": {}, "required": []}},
 "atrium.noop_write": {"risk": "write", "params": {"type": "object", "additionalProperties": false, "properties": {"echo": {"type": "string", "maxLength": 64}}, "required": ["echo"]}},
 "atrium.receipt": {"risk": "read", "params": {"type": "object", "additionalProperties": false, "properties": {"jti": {"type": "string", "maxLength": 64}}, "required": ["jti"]}},
 "atrium.panel.pull": {"risk": "read", "params": {"type": "object", "additionalProperties": false, "properties": {"wait": {"type": "integer", "minimum": 0, "maximum": 25}}, "required": []}},
 "atrium.panel.answer": {"risk": "propose", "params": {"type": "object", "additionalProperties": false, "properties": {"question_id": {"type": "string", "maxLength": 64}, "text": {"type": "string", "maxLength": 4000}, "status": {"enum": ["answered", "escalated", "declined", "working"]}, "by": {"type": "string", "maxLength": 80}}, "required": ["question_id", "text", "status"]}},
 "atrium.events.pull": {"risk": "read", "params": {"type": "object", "additionalProperties": false, "properties": {"after": {"type": "integer", "minimum": 0, "maximum": 9007199254740991}, "wait": {"type": "integer", "minimum": 0, "maximum": 25}}, "required": []}}
}`
	builtins = mustBuiltins()

	actionIDRE     = regexp.MustCompile(`^[a-z][a-z0-9_.]{2,57}$`)
	toolIDRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	subsidiaryIDRE = regexp.MustCompile(`^sub_[0-9a-f]{12}$`)
	paramNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	dateRE         = regexp.MustCompile(`^[0-9]{1,12}$`)
	questionIDRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	b64uRE         = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	textControl    = regexp.MustCompile("[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")

	errBad = errors.New("bad")
)

// Refusal is a refused request: its answer is {"ok": false, "code": Code} and never echoes request content.
type Refusal struct{ Code string }

func (r *Refusal) Error() string { return r.Code }
func refuse(code string) *Refusal { return &Refusal{Code: code} }

// User is a tool user: the panel's signed-in user, and in panel runs the user a call acts for.
type User struct {
	ID      string   `json:"id"`
	Display string   `json:"display"`
	Roles   []string `json:"roles"`
}

// Ctx is what a handler gets besides its params. User is set in panel runs: the tool user who asked, from the
// bridge's own question store (never from the sidecar) - authorize as that user AND the service principal.
type Ctx struct {
	Context    context.Context
	Action     string
	Principal  string
	User       *User
	QuestionID string
	GrantJTI   string
	Request    *http.Request
	bridge     *Bridge
}

// Emit queues a declared event caused by this call (it carries the grant's jti for granted calls).
func (c *Ctx) Emit(name string, payload map[string]any) bool { return c.bridge.EmitContext(c.Context, name, payload) }

// Handler runs one action through the tool's service layer as the service principal. Params are validated against
// the manifest's schema before it runs: strings, bools, int64 integers and []any arrays.
type Handler func(params map[string]any, ctx *Ctx) (any, error)

// GrantStore keeps used grant jtis and their receipts; persist them where the tool has storage (FileGrants or the
// tool's database), so a restart cannot replay a grant. Mark is the authoritative single-use check: it records the
// jti and answers true at once, or false when it was already used.
type GrantStore interface {
	Used(jti string) bool
	Mark(jti string, keepUntil, now int64) bool // before the handler runs
	Record(jti, status string, at int64)
	Receipt(jti string) (status string, at int64, ok bool)
}

// NonceStore keeps the nonces seen in the last 180 s: Add refuses a seen one ("replay") and refuses when full
// ("busy") rather than forget one. Share it when the tool runs several processes.
type NonceStore interface {
	Add(nonce string, now int64) error
}

type memoryNonces struct {
	mu   sync.Mutex
	seen map[string]int64
	list []string
}

// NewMemoryNonces is the default, in-process nonce store.
func NewMemoryNonces() NonceStore { return &memoryNonces{seen: map[string]int64{}} }

func (n *memoryNonces) Add(nonce string, now int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	for len(n.list) > 0 {
		first := n.list[0]
		if n.seen[first] > now-nonceTTL {
			break
		}
		delete(n.seen, first)
		n.list = n.list[1:]
	}
	if _, seen := n.seen[nonce]; seen {
		return refuse("replay")
	}
	if len(n.seen) >= nonceCapacity {
		return refuse("busy")
	}
	n.seen[nonce] = now
	n.list = append(n.list, nonce)
	return nil
}

// Glue is the tool-specific part of the bridge.
type Glue struct {
	Actions          map[string]Handler
	CurrentUser      func(r *http.Request) *User // nil disables the panel
	ServicePrincipal string                      // default "atrium-team"
	Manifest         []byte                      // the committed atrium-bridge.json (default: ManifestPath)
	ManifestPath     string                      // default: atrium-bridge.json in the working directory or by the binary
	PanelJS          []byte                      // default: the vendored panel.js embedded in this package
	PanelSHA256      string                      // default: PanelJSSHA256
	Env              func(string) string         // default: os.Getenv
	Clock            func() time.Time            // default: time.Now
	Grants           GrantStore                  // default: in memory
	Nonces           NonceStore                  // default: in memory
	MaxWait          time.Duration               // long-poll cap, default 25 s
}

type prop struct {
	kind                 string
	maxLength, minLength int
	minimum, maximum     int64
	enumStr              []string
	enumInt              []int64
	maxItems             int
	items                *prop
}

type schema struct {
	props    map[string]*prop
	required []string
}

type actionSpec struct {
	id         string
	risk       string
	onBehalfOf bool
	params     *schema
}

type question struct {
	ID        string
	User      User
	Text      string
	Page      map[string]string
	AskedAt   int64
	Status    string
	Answer    *string
	By        string
	UpdatedAt int64
}

func (q *question) open() bool { return q.Status == "waiting" || q.Status == "answering" }

type event struct {
	Seq     int64             `json:"seq"`
	Name    string            `json:"name"`
	Payload json.RawMessage   `json:"payload"`
	At      int64             `json:"at"`
	Cause   map[string]string `json:"cause,omitempty"`
}

// Bridge serves /.atrium/ (an http.Handler).
type Bridge struct {
	glue        Glue
	principal   string
	clock       func() time.Time
	grants      GrantStore
	maxWait     time.Duration
	keys        []ed25519.PublicKey
	tool, sub   string
	allow       []netip.Prefix
	manifest    map[string]any
	manifestRaw []byte
	actions     map[string]*actionSpec
	eventNames  map[string]bool
	panelJS     []byte
	panelSHA    string
	panelOn     bool
	panelRoles  []string
	problem     string

	mu        sync.Mutex
	nonces    NonceStore
	calls     []int64
	rate      map[string]int64
	questions map[string]*question
	order     []string
	asked     map[string][]int64
	lastPull  int64
	events    []event
	seq       int64
	drops     int64
	rejected  int64
}

var (
	defaultMu     sync.Mutex
	defaultBridge *Bridge
)

type causeKey struct{}

// New builds the bridge; it never fails: without valid configuration every route but /health answers 503
// not_configured and the tool works unchanged (Problem says why).
func New(g Glue) *Bridge {
	b := &Bridge{glue: g, principal: g.ServicePrincipal, clock: g.Clock, grants: g.Grants, maxWait: g.MaxWait,
		nonces: g.Nonces, rate: copyRate(defaultRate), questions: map[string]*question{},
		asked: map[string][]int64{}, lastPull: -1}
	if b.principal == "" {
		b.principal = "atrium-team"
	}
	if b.clock == nil {
		b.clock = time.Now
	}
	if b.grants == nil {
		b.grants = NewMemoryGrants()
	}
	if b.nonces == nil {
		b.nonces = NewMemoryNonces()
	}
	if b.maxWait <= 0 || b.maxWait > waitMax*time.Second {
		b.maxWait = waitMax * time.Second
	}
	env := g.Env
	if env == nil {
		env = os.Getenv
	}
	if err := b.configure(env); err != nil {
		b.keys = nil
		b.problem = truncate("not configured: "+err.Error(), 300)
		log.Printf("Atrium bridge %s", b.problem)
	}
	defaultMu.Lock()
	defaultBridge = b
	defaultMu.Unlock()
	return b
}

// Ready says whether the bridge is configured; Problem says why not.
func (b *Bridge) Ready() bool     { return len(b.keys) > 0 }
func (b *Bridge) Problem() string { return b.problem }

func (b *Bridge) configure(env func(string) string) error {
	keys, err := ParseKeys(env("ATRIUM_BRIDGE_KEYS"))
	if err != nil {
		return err
	}
	b.tool, b.sub = env("ATRIUM_TOOL_ID"), env("ATRIUM_SUBSIDIARY_ID")
	if !toolIDRE.MatchString(b.tool) || !subsidiaryIDRE.MatchString(b.sub) {
		return errors.New("ATRIUM_TOOL_ID or ATRIUM_SUBSIDIARY_ID is missing or malformed")
	}
	for _, item := range strings.Split(env("ATRIUM_BRIDGE_ALLOW"), ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			addr, err2 := netip.ParseAddr(item)
			if err2 != nil {
				return errors.New("ATRIUM_BRIDGE_ALLOW: not a CIDR list")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		b.allow = append(b.allow, prefix.Masked())
	}
	raw := b.glue.Manifest
	if raw == nil {
		if raw, err = readManifest(b.glue.ManifestPath); err != nil {
			return err
		}
	}
	b.manifestRaw = raw
	parsed, err := parseJSON(raw)
	manifest, ok := parsed.(map[string]any)
	if err != nil || !ok || manifest["contract"] != Contract || manifest["tool_id"] != b.tool {
		return errors.New("atrium-bridge.json is not this tool's atrium-bridge/1 manifest")
	}
	b.manifest, b.actions, b.eventNames = manifest, map[string]*actionSpec{}, map[string]bool{}
	list, _ := manifest["actions"].([]any)
	if _, present := manifest["actions"]; present && list == nil || len(list) > maxActions {
		return errors.New("atrium-bridge.json lists too many actions")
	}
	for _, item := range list {
		a, ok := item.(map[string]any)
		id, _ := a["id"].(string)
		risk, _ := a["risk"].(string)
		sch, err := compileSchema(a["params"])
		if !ok || !actionIDRE.MatchString(id) || strings.HasPrefix(id, "atrium.") || !oneOf(risk, "read", "propose", "write", "admin") || err != nil {
			return fmt.Errorf("atrium-bridge.json action %q breaks the contract", truncate(id, 60))
		}
		obo, _ := a["on_behalf_of"].(bool)
		if b.glue.Actions[id] == nil {
			log.Printf("Atrium bridge: the glue has no handler for %s", id)
			continue
		}
		b.actions[id] = &actionSpec{id: id, risk: risk, onBehalfOf: obo, params: sch}
	}
	if events, ok := manifest["events"].(map[string]any); ok {
		names, _ := events["names"].([]any)
		for _, n := range names {
			if s, ok := n.(string); ok {
				b.eventNames[s] = true
			}
		}
	}
	b.keys = keys
	panel, sum := b.glue.PanelJS, b.glue.PanelSHA256
	if panel == nil {
		panel = vendoredPanel
	}
	if sum == "" {
		sum = PanelJSSHA256
	}
	if digest := sha256.Sum256(panel); hex.EncodeToString(digest[:]) == sum {
		b.panelJS, b.panelSHA = panel, sum
	} else {
		log.Printf("Atrium bridge panel off: panel.js is not the vendored widget (SHA-256 differs)")
	}
	panelObj, _ := manifest["panel"].(map[string]any)
	enabled, _ := panelObj["enabled"].(bool)
	b.panelOn = strings.ToLower(strings.TrimSpace(env("ATRIUM_PANEL"))) != "off" && b.glue.CurrentUser != nil &&
		b.panelJS != nil && enabled
	for _, r := range strings.Split(env("ATRIUM_PANEL_ROLES"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			b.panelRoles = append(b.panelRoles, r)
		}
	}
	return nil
}

func readManifest(path string) ([]byte, error) {
	candidates := []string{path}
	if path == "" {
		candidates = []string{"atrium-bridge.json"}
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "atrium-bridge.json"))
		}
	}
	for _, c := range candidates {
		if raw, err := os.ReadFile(c); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("atrium-bridge.json not found")
}

// ---- encodings, keys, tickets and grants ----

// B64uDecode is strict base64url without padding: the alphabet only, canonical.
func B64uDecode(text string) ([]byte, error) {
	if !b64uRE.MatchString(text) || len(text)%4 == 1 {
		return nil, errBad
	}
	return base64.RawURLEncoding.Strict().DecodeString(text)
}

func b64u(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func publicKey(text string) (ed25519.PublicKey, error) {
	raw, err := B64uDecode(text)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("an Ed25519 public key is 32 bytes of base64url")
	}
	return ed25519.PublicKey(raw), nil
}

// ParseKeys reads ATRIUM_BRIDGE_KEYS: one or two base64url public keys, comma-separated.
func ParseKeys(value string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		key, err := publicKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) < 1 || len(keys) > maxKeys {
		return nil, errors.New("ATRIUM_BRIDGE_KEYS holds one or two keys")
	}
	return keys, nil
}

func parseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errBad
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errBad
	}
	return value, nil
}

// VerifyToken verifies the signature over the received "<prefix>.<payload>" bytes with each key, THEN parses.
func VerifyToken(token, prefix string, keys []ed25519.PublicKey, code string) (map[string]any, error) {
	if len(token) > maxToken || len(keys) == 0 {
		return nil, refuse(code)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != prefix || !b64uRE.MatchString(parts[1]) {
		return nil, refuse(code)
	}
	signature, err := B64uDecode(parts[2])
	if err != nil {
		return nil, refuse(code)
	}
	signed := []byte(parts[0] + "." + parts[1])
	verified := false
	for i, key := range keys {
		if i < maxKeys && len(signature) == ed25519.SignatureSize && ed25519.Verify(key, signed, signature) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, refuse(code)
	}
	raw, err := B64uDecode(parts[1])
	if err != nil || len(raw) > maxTokenPayload {
		return nil, refuse(code)
	}
	value, err := parseJSON(raw)
	payload, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, refuse(code)
	}
	if v, ok := intOf(payload["v"]); !ok || v != 1 {
		return nil, refuse(code)
	}
	return payload, nil
}

// intOf: an integer JSON number written without a fraction or exponent (as the issuer writes them).
func intOf(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func str(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok
}

// TicketFieldsOK checks a verified ticket payload's fields.
func TicketFieldsOK(p map[string]any) bool {
	typ, _ := str(p["typ"])
	_, okSub := str(p["sub"])
	_, okTool := str(p["tool"])
	_, okCV := intOf(p["cv"])
	mode, _ := str(p["mode"])
	act, okAct := p["act"].([]any)
	cnf, okCnf := str(p["cnf"])
	_, okIat := intOf(p["iat"])
	_, okExp := intOf(p["exp"])
	jti, _ := str(p["jti"])
	rl, okRl := p["rl"].(map[string]any)
	if typ != "ticket" || !okSub || !okTool || !okCV || (mode != "probation" && mode != "active") || !okAct ||
		len(act) > maxActions+len(builtins) || !okCnf || !okIat || !okExp || len(jti) == 0 || len(jti) > 64 || !okRl {
		return false
	}
	for _, a := range act {
		if _, ok := a.(string); !ok {
			return false
		}
	}
	for _, v := range rl {
		if n, ok := intOf(v); !ok || n < 0 {
			return false
		}
	}
	_, err := publicKey(cnf)
	return err == nil
}

// GrantFieldsOK checks a verified grant payload's fields.
func GrantFieldsOK(p map[string]any) bool {
	typ, _ := str(p["typ"])
	_, a := str(p["sub"])
	_, b := str(p["tool"])
	_, c := intOf(p["cv"])
	_, d := str(p["act"])
	_, e := str(p["bh"])
	_, f := str(p["apv"])
	_, g := intOf(p["iat"])
	_, h := intOf(p["exp"])
	jti, _ := str(p["jti"])
	return typ == "grant" && a && b && c && d && e && f && g && h && len(jti) > 0 && len(jti) <= 64
}

// CheckTicket checks a well-formed ticket against the bridge's tool, subsidiary and clock (with the leeway).
func CheckTicket(p map[string]any, tool, sub string, now int64) error {
	iat, _ := intOf(p["iat"])
	exp, _ := intOf(p["exp"])
	if p["tool"] != tool || p["sub"] != sub || iat > now+clockLeeway {
		return refuse("bad_ticket")
	}
	if exp <= now-clockLeeway {
		return refuse("expired")
	}
	return nil
}

// CheckGrant checks a well-formed grant against the call: tool, subsidiary, action, body hash (constant time), expiry.
func CheckGrant(p map[string]any, tool, sub, action string, body []byte, now int64) error {
	bh, _ := p["bh"].(string)
	expected := BodyHash(body)
	if p["tool"] != tool || p["sub"] != sub || p["act"] != action ||
		subtle.ConstantTimeCompare([]byte(bh), []byte(expected)) != 1 {
		return refuse("grant_mismatch")
	}
	if exp, _ := intOf(p["exp"]); exp <= now-clockLeeway {
		return refuse("expired")
	}
	return nil
}

// BodyHash is a grant's bh: base64url SHA-256 of the exact body bytes.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return b64u(sum[:])
}

// SigningString is the nine lines a request signature covers.
func SigningString(method, path, date, nonce string, body []byte, ticketJTI, grantJTI, onBehalfOf string) []byte {
	sum := sha256.Sum256(body)
	if grantJTI == "" {
		grantJTI = "-"
	}
	if onBehalfOf == "" {
		onBehalfOf = "-"
	}
	return []byte(strings.Join([]string{Contract, strings.ToUpper(method), path, date, nonce, hex.EncodeToString(sum[:]),
		ticketJTI, grantJTI, onBehalfOf}, "\n"))
}

// VerifySignature checks a request signature against the ticket's cnf.
func VerifySignature(cnf, signature string, message []byte) bool {
	key, err := publicKey(cnf)
	if err != nil {
		return false
	}
	sig, err := B64uDecode(signature)
	return err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, message, sig)
}

// ---- params: the JSON Schema subset ----

func compileProp(raw any, item bool) (*prop, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errBad
	}
	p := &prop{minimum: -maxSafeInt, maximum: maxSafeInt}
	if _, isEnum := m["enum"]; isEnum {
		p.kind = "enum"
	} else if t, _ := str(m["type"]); oneOf(t, "string", "integer", "boolean", "array") {
		p.kind = t
	} else {
		return nil, errBad
	}
	if item && p.kind == "array" {
		return nil, errBad
	}
	allowed := map[string][]string{"string": {"type", "maxLength", "minLength"}, "integer": {"type", "minimum", "maximum"},
		"boolean": {"type"}, "enum": {"type", "enum"}, "array": {"type", "items", "maxItems"}}[p.kind]
	for key := range m {
		if key != "description" && !oneOf(key, allowed...) {
			return nil, errBad
		}
	}
	switch p.kind {
	case "string":
		top, ok1 := intOf(m["maxLength"])
		low, ok2 := int64(0), true
		if _, present := m["minLength"]; present {
			low, ok2 = intOf(m["minLength"])
		}
		if !ok1 || !ok2 || top < 1 || top > maxString || low < 0 || low > top {
			return nil, errBad
		}
		p.maxLength, p.minLength = int(top), int(low)
	case "integer":
		for key, target := range map[string]*int64{"minimum": &p.minimum, "maximum": &p.maximum} {
			if _, present := m[key]; present {
				v, ok := intOf(m[key])
				if !ok || v < -maxSafeInt || v > maxSafeInt {
					return nil, errBad
				}
				*target = v
			}
		}
		if p.minimum > p.maximum {
			return nil, errBad
		}
	case "enum":
		values, ok := m["enum"].([]any)
		if !ok || len(values) < 1 || len(values) > maxEnum {
			return nil, errBad
		}
		seenS, seenI := map[string]bool{}, map[int64]bool{}
		for _, v := range values {
			if s, ok := v.(string); ok && p.enumInt == nil {
				if seenS[s] {
					return nil, errBad
				}
				seenS[s] = true
				p.enumStr = append(p.enumStr, s)
			} else if n, ok := intOf(v); ok && p.enumStr == nil && n >= -maxSafeInt && n <= maxSafeInt {
				if seenI[n] {
					return nil, errBad
				}
				seenI[n] = true
				p.enumInt = append(p.enumInt, n)
			} else {
				return nil, errBad
			}
		}
	case "array":
		top, ok := intOf(m["maxItems"])
		if !ok || top < 1 || top > maxItems {
			return nil, errBad
		}
		items, err := compileProp(m["items"], true)
		if err != nil {
			return nil, err
		}
		p.maxItems, p.items = int(top), items
	}
	return p, nil
}

func compileSchema(raw any) (*schema, error) {
	m, ok := raw.(map[string]any)
	if !ok || m["type"] != "object" || m["additionalProperties"] != false {
		return nil, errBad
	}
	for key := range m {
		if !oneOf(key, "type", "additionalProperties", "properties", "required", "description") {
			return nil, errBad
		}
	}
	s := &schema{props: map[string]*prop{}}
	props, ok := m["properties"].(map[string]any)
	if _, present := m["properties"]; present && !ok || len(props) > maxProperties {
		return nil, errBad
	}
	for name, value := range props {
		p, err := compileProp(value, false)
		if err != nil || !paramNameRE.MatchString(name) {
			return nil, errBad
		}
		s.props[name] = p
	}
	required, ok := m["required"].([]any)
	if _, present := m["required"]; present && !ok {
		return nil, errBad
	}
	for _, r := range required {
		name, ok := r.(string)
		if !ok || s.props[name] == nil {
			return nil, errBad
		}
		s.required = append(s.required, name)
	}
	return s, nil
}

func mustBuiltins() map[string]*actionSpec {
	parsed, err := parseJSON([]byte(builtinsJSON))
	if err != nil {
		panic(err)
	}
	out := map[string]*actionSpec{}
	for id, raw := range parsed.(map[string]any) {
		m := raw.(map[string]any)
		sch, err := compileSchema(m["params"])
		if err != nil {
			panic(err)
		}
		out[id] = &actionSpec{id: id, risk: m["risk"].(string), params: sch}
	}
	return out
}

// numberInt: a JSON number that is an integer within +-(2^53-1); 2.0 and 1e1 count, as in every bridge language.
func numberInt(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	if !strings.ContainsAny(string(n), ".eE") {
		i, err := strconv.ParseInt(string(n), 10, 64)
		return i, err == nil && i >= -maxSafeInt && i <= maxSafeInt
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > maxSafeInt {
		return 0, false
	}
	return int64(f), true
}

func checkValue(p *prop, value any) (any, bool) {
	switch p.kind {
	case "array":
		list, ok := value.([]any)
		if !ok || len(list) > p.maxItems {
			return nil, false
		}
		out := make([]any, 0, len(list))
		for _, v := range list {
			item, ok := checkValue(p.items, v)
			if !ok {
				return nil, false
			}
			out = append(out, item)
		}
		return out, true
	case "boolean":
		v, ok := value.(bool)
		return v, ok
	case "string":
		s, ok := value.(string)
		n := utf8.RuneCountInString(s)
		return s, ok && n >= p.minLength && n <= p.maxLength
	case "integer":
		i, ok := numberInt(value)
		return i, ok && i >= p.minimum && i <= p.maximum
	case "enum":
		if s, ok := value.(string); ok {
			return s, oneOf(s, p.enumStr...)
		}
		if i, ok := numberInt(value); ok {
			for _, e := range p.enumInt {
				if e == i {
					return i, true
				}
			}
		}
	}
	return nil, false
}

// ValidateParams checks params against an action's schema (422 bad_params on any problem).
func validateParams(s *schema, params map[string]any) (map[string]any, error) {
	for key := range params {
		if s.props[key] == nil {
			return nil, refuse("bad_params")
		}
	}
	for _, r := range s.required {
		if _, ok := params[r]; !ok {
			return nil, refuse("bad_params")
		}
	}
	out := map[string]any{}
	for key, value := range params {
		v, ok := checkValue(s.props[key], value)
		if !ok {
			return nil, refuse("bad_params")
		}
		out[key] = v
	}
	return out, nil
}

func parseBody(body []byte) (map[string]any, error) {
	value, err := parseJSON(body)
	data, ok := value.(map[string]any)
	if err != nil || !ok || len(data) != 1 {
		return nil, refuse("bad_params")
	}
	params, ok := data["params"].(map[string]any)
	if !ok {
		return nil, refuse("bad_params")
	}
	return params, nil
}

// ValidateBody parses a call body against a schema given as JSON (for tests and tools).
func ValidateBody(schemaJSON, body []byte) (map[string]any, error) {
	raw, err := parseJSON(schemaJSON)
	if err != nil {
		return nil, err
	}
	s, err := compileSchema(raw)
	if err != nil {
		return nil, err
	}
	params, err := parseBody(body)
	if err != nil {
		return nil, err
	}
	return validateParams(s, params)
}

// ---- stores ----

type grantRow struct {
	Status    string `json:"status"`
	At        int64  `json:"at"`
	KeepUntil int64  `json:"keep_until"`
}

// MemoryGrants keeps used grant jtis in memory.
type MemoryGrants struct {
	mu   sync.Mutex
	rows map[string]*grantRow
	save func(map[string]*grantRow)
}

func NewMemoryGrants() *MemoryGrants { return &MemoryGrants{rows: map[string]*grantRow{}} }

// NewFileGrants keeps used grant jtis in a JSON file (written atomically on every change).
func NewFileGrants(path string) *MemoryGrants {
	g := NewMemoryGrants()
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &g.rows)
		if g.rows == nil {
			g.rows = map[string]*grantRow{}
		}
	}
	g.save = func(rows map[string]*grantRow) {
		raw, err := json.Marshal(rows)
		if err == nil && os.WriteFile(path+".tmp", raw, 0o600) == nil {
			_ = os.Rename(path+".tmp", path)
		}
	}
	return g
}

func (g *MemoryGrants) Used(jti string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.rows[jti] != nil
}

func (g *MemoryGrants) Mark(jti string, keepUntil, now int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, row := range g.rows {
		if row.KeepUntil <= now {
			delete(g.rows, key)
		}
	}
	if g.rows[jti] != nil {
		return false
	}
	g.rows[jti] = &grantRow{Status: "started", At: now, KeepUntil: keepUntil}
	if g.save != nil {
		g.save(g.rows)
	}
	return true
}

func (g *MemoryGrants) Record(jti, status string, at int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if row := g.rows[jti]; row != nil {
		row.Status, row.At = status, at
		if g.save != nil {
			g.save(g.rows)
		}
	}
}

func (g *MemoryGrants) Receipt(jti string) (string, int64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if row := g.rows[jti]; row != nil {
		return row.Status, row.At, true
	}
	return "", 0, false
}

// ---- serving ----

type request struct {
	method, path, query string
	header              http.Header
	body                []byte
	oversize            bool
	remote              string
	native              *http.Request
}

type response struct {
	status int
	header map[string]string
	body   []byte
}

func jsonAnswer(status int, value any) response {
	body, err := json.Marshal(value)
	if err != nil {
		body = []byte(`{"ok":false,"code":"bad_result"}`)
		status = 500
	}
	return response{status, map[string]string{"Content-Type": "application/json", "X-Content-Type-Options": "nosniff",
		"Cache-Control": "no-store"}, body}
}

func refusalAnswer(code string) response {
	status, ok := statuses[code]
	if !ok {
		status = 500
	}
	return jsonAnswer(status, map[string]any{"ok": false, "code": code})
}

func bridgePath(path string) string {
	if at := strings.Index(path, "/.atrium/"); at >= 0 {
		return path[at:]
	}
	return "/.atrium" + path // mounted with http.StripPrefix("/.atrium", ...)
}

// ServeHTTP answers every /.atrium/ route.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := request{method: strings.ToUpper(r.Method), path: bridgePath(r.URL.Path), query: r.URL.RawQuery,
		header: r.Header, remote: r.RemoteAddr, native: r}
	if r.ContentLength > MaxBody {
		req.oversize = true
	} else if req.method == "POST" && r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		req.body, req.oversize = body, err != nil || len(body) > MaxBody
		if req.oversize {
			req.body = nil
		}
	}
	out := b.handle(r.Context(), req)
	for k, v := range out.header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(out.body)))
	w.WriteHeader(out.status)
	_, _ = w.Write(out.body)
}

func (b *Bridge) handle(ctx context.Context, req request) (out response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("Atrium bridge: internal error")
			out = jsonAnswer(500, map[string]any{"ok": false, "code": "failed"})
		}
	}()
	if req.path == healthPath && req.method == "GET" {
		return jsonAnswer(200, map[string]string{"status": "ok"})
	}
	if !b.Ready() {
		return refusalAnswer("not_configured")
	}
	switch {
	case req.path == panelJSPath && req.method == "GET":
		if b.panelJS == nil {
			return jsonAnswer(404, map[string]any{"ok": false, "code": "not_found"})
		}
		etag := `"` + b.panelSHA + `"`
		header := map[string]string{"Content-Type": "application/javascript; charset=utf-8",
			"X-Content-Type-Options": "nosniff", "ETag": etag, "Cache-Control": "no-cache"}
		if req.header.Get("If-None-Match") == etag {
			return response{304, header, nil}
		}
		return response{200, header, b.panelJS}
	case req.method == "POST" && strings.HasPrefix(req.path, callPrefix):
		call, err := b.verify(ctx, req)
		if err != nil {
			return refusalOf(err)
		}
		result, status := b.run(call)
		return b.finish(call, result, status)
	case (req.method == "POST" && req.path == panelAskPath) ||
		(req.method == "GET" && (req.path == panelStatusPath || strings.HasPrefix(req.path, panelQuestionPrefix))):
		var user *User
		if b.glue.CurrentUser != nil {
			user = normalUser(b.glue.CurrentUser(req.native))
		}
		out, err := b.panel(req, user)
		if err != nil {
			return refusalOf(err)
		}
		return out
	}
	return jsonAnswer(404, map[string]any{"ok": false, "code": "not_found"})
}

func refusalOf(err error) response {
	var r *Refusal
	if errors.As(err, &r) {
		return refusalAnswer(r.Code)
	}
	return jsonAnswer(500, map[string]any{"ok": false, "code": "failed"})
}

type call struct {
	action string
	spec   *actionSpec
	params map[string]any
	ctx    *Ctx
	ticket map[string]any
	wait   int64
}

// ---- the verification order (one code path for every call) ----

func (b *Bridge) verify(parent context.Context, req request) (*call, error) {
	action := req.path[len(callPrefix):]
	now := b.clock().Unix()
	if len(b.allow) > 0 && !b.sourceAllowed(req.remote) { // 1
		return nil, refuse("source_not_allowed")
	}
	if req.oversize || len(req.body) > MaxBody {
		return nil, refuse("too_large")
	}
	ticket, err := VerifyToken(req.header.Get("Atrium-Ticket"), "AT1", b.keys, "bad_ticket") // 2
	if err != nil {
		return nil, err
	}
	if !TicketFieldsOK(ticket) {
		return nil, refuse("bad_ticket")
	}
	if err := CheckTicket(ticket, b.tool, b.sub, now); err != nil {
		return nil, err
	}
	var grant map[string]any // 3
	grantJTI := ""
	if values, present := req.header["Atrium-Grant"]; present {
		if grant, err = VerifyToken(strings.Join(values, ", "), "AG1", b.keys, "grant_mismatch"); err != nil {
			return nil, err
		}
		if !GrantFieldsOK(grant) {
			return nil, refuse("grant_mismatch")
		}
		grantJTI = grant["jti"].(string)
	}
	date, nonce, signature := req.header.Get("Atrium-Date"), req.header.Get("Atrium-Nonce"), req.header.Get("Atrium-Signature")
	obo, hasOBO := "", false
	if values, present := req.header["Atrium-On-Behalf-Of"]; present {
		obo, hasOBO = strings.Join(values, ", "), true
	}
	_, hasDate := req.header["Atrium-Date"]
	_, hasSig := req.header["Atrium-Signature"]
	if !hasDate || !hasSig || !dateRE.MatchString(date) || !b64uRE.MatchString(nonce) || len(nonce) < 16 ||
		len(nonce) > 64 || (hasOBO && !questionIDRE.MatchString(obo)) {
		return nil, refuse("bad_signature")
	}
	path := callPrefix + action
	if req.query != "" {
		path += "?" + req.query
	}
	message := SigningString("POST", path, date, nonce, req.body, ticket["jti"].(string), grantJTI, obo)
	if !VerifySignature(ticket["cnf"].(string), signature, message) {
		return nil, refuse("bad_signature")
	}
	if d, _ := strconv.ParseInt(date, 10, 64); d-now > clockLeeway || now-d > clockLeeway {
		return nil, refuse("expired")
	}
	if err := b.nonces.Add(nonce, now); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.rate = copyRate(defaultRate)
	for k, v := range ticket["rl"].(map[string]any) {
		if n, ok := intOf(v); ok {
			b.rate[k] = n
		}
	}
	b.mu.Unlock()
	if ticket["mode"] == "probation" && !oneOf(action, probationBuiltins...) { // 4
		return nil, refuse("probation")
	}
	spec := builtins[action]
	if spec == nil {
		spec = b.actions[action]
	}
	allowed := false
	for _, a := range ticket["act"].([]any) {
		allowed = allowed || a == action
	}
	if !allowed || spec == nil {
		return nil, refuse("action_not_allowed")
	}
	raw, err := parseBody(req.body) // 5
	if err != nil {
		return nil, err
	}
	params, err := validateParams(spec.params, raw)
	if err != nil {
		return nil, err
	}
	granted := ""
	if spec.risk == "write" || spec.risk == "admin" { // 6
		if grant == nil {
			return nil, refuse("grant_required")
		}
		if err := CheckGrant(grant, b.tool, b.sub, action, req.body, now); err != nil {
			return nil, err
		}
		if b.grants.Used(grantJTI) {
			return nil, refuse("grant_used")
		}
		granted = grantJTI
	}
	var user *User
	if hasOBO { // 7
		b.mu.Lock()
		b.sweep(now)
		q := b.questions[obo]
		// only read and propose actions act for a tool user, whatever a local manifest says
		if q != nil && q.open() && spec.onBehalfOf && (spec.risk == "read" || spec.risk == "propose") {
			copied := q.User
			copied.Roles = append([]string(nil), q.User.Roles...)
			user = &copied
		}
		b.mu.Unlock()
		if user == nil {
			return nil, refuse("forbidden_on_behalf")
		}
	}
	b.mu.Lock() // 8
	for len(b.calls) > 0 && b.calls[0] <= now-60 {
		b.calls = b.calls[1:]
	}
	if int64(len(b.calls)) >= b.rate["calls_per_min"] {
		b.mu.Unlock()
		return nil, refuse("rate_limited")
	}
	b.calls = append(b.calls, now)
	b.mu.Unlock()
	if granted != "" { // single use: marked before the handler runs
		if gexp, _ := intOf(grant["exp"]); !b.grants.Mark(granted, gexp+grantJTIKeep, now) {
			return nil, refuse("grant_used")
		}
	}
	ctx := parent
	if granted != "" {
		ctx = context.WithValue(parent, causeKey{}, granted)
	}
	wait, _ := params["wait"].(int64)
	return &call{action: action, spec: spec, params: params, ticket: ticket, wait: wait, ctx: &Ctx{Context: ctx, Action: action, Principal: b.principal, User: user, QuestionID: obo,
			GrantJTI: granted, Request: req.native, bridge: b}}, nil
}

func (b *Bridge) sourceAllowed(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range b.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ---- running ----

func (b *Bridge) builtin(c *call) any {
	now := b.clock().Unix()
	switch c.action {
	case "atrium.ping":
		sum := sha256.Sum256(b.manifestRaw)
		b.mu.Lock()
		defer b.mu.Unlock()
		return map[string]any{"tool": b.tool, "contract": Contract, "core": CoreVersion,
			"manifest_sha256": hex.EncodeToString(sum[:]), "time": now, "drops": b.drops, "rejected": b.rejected}
	case "atrium.describe":
		return json.RawMessage(b.manifestRaw)
	case "atrium.noop_write":
		return map[string]any{"executed": true, "echo": c.params["echo"]}
	case "atrium.receipt":
		status, at, ok := b.grants.Receipt(c.params["jti"].(string))
		if !ok {
			return map[string]any{"status": "unused"}
		}
		if status == "started" { // used, but the bridge stopped before recording the outcome: never "unused"
			status = "unknown"
		}
		return map[string]any{"status": status, "at": at}
	case "atrium.panel.pull":
		return b.pullQuestions(now)
	case "atrium.panel.answer":
		return b.panelAnswer(c.params, now)
	case "atrium.events.pull":
		after, _ := c.params["after"].(int64)
		return b.pullEvents(after, now)
	}
	panic("unknown built-in")
}

func empty(action string, result any) bool {
	switch action {
	case "atrium.panel.pull":
		return len(result.([]map[string]any)) == 0
	case "atrium.events.pull":
		return len(result.(map[string]any)["events"].([]event)) == 0
	}
	return false
}

func (b *Bridge) run(c *call) (result any, status string) {
	if builtins[c.action] != nil {
		result = b.builtin(c)
		wait := time.Duration(c.wait) * time.Second
		if wait > b.maxWait {
			wait = b.maxWait
		}
		deadline := time.Now().Add(wait)
		for empty(c.action, result) && time.Now().Before(deadline) && c.ctx.Context.Err() == nil {
			time.Sleep(200 * time.Millisecond)
			result = b.builtin(c)
		}
		return result, "executed"
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("Atrium bridge: the handler of %s panicked", c.action)
			result, status = nil, "failed"
		}
	}()
	out, err := b.glue.Actions[c.action](c.params, c.ctx)
	if err != nil {
		log.Printf("Atrium bridge: the handler of %s failed", c.action)
		return nil, "failed"
	}
	return out, "executed"
}

func (b *Bridge) finish(c *call, result any, status string) response {
	now := b.clock().Unix()
	var receipt any
	if jti := c.ctx.GrantJTI; jti != "" { // 10
		b.grants.Record(jti, status, now)
		receipt = map[string]any{"jti": jti, "status": status, "at": now}
	}
	if status == "failed" {
		return jsonAnswer(500, map[string]any{"ok": false, "code": "failed", "receipt": receipt})
	}
	body, err := json.Marshal(map[string]any{"ok": true, "result": result, "receipt": receipt})
	if err != nil {
		return jsonAnswer(500, map[string]any{"ok": false, "code": "bad_result", "receipt": receipt})
	}
	if len(body) > MaxResponse {
		return jsonAnswer(500, map[string]any{"ok": false, "code": "result_too_large", "receipt": receipt})
	}
	out := jsonAnswer(200, nil)
	out.body = body
	return out
}

// ---- the panel ----

func normalUser(u *User) *User {
	if u == nil || strings.TrimSpace(u.ID) == "" {
		return nil
	}
	out := &User{ID: truncate(u.ID, 120), Display: truncate(textControl.ReplaceAllString(u.Display, ""), 120)}
	if out.Display == "" {
		out.Display = out.ID
	}
	for i, r := range u.Roles {
		if i < 20 {
			out.Roles = append(out.Roles, truncate(r, 60))
		}
	}
	if out.Roles == nil {
		out.Roles = []string{}
	}
	return out
}

func (b *Bridge) panelFor(user *User) bool {
	if !b.panelOn || user == nil {
		return false
	}
	if len(b.panelRoles) == 0 {
		return true
	}
	for _, r := range user.Roles {
		if oneOf(r, b.panelRoles...) {
			return true
		}
	}
	return false
}

func (b *Bridge) panel(req request, user *User) (response, error) {
	if req.header.Get("X-Atrium-Panel") != "1" {
		return response{}, refuse("panel_header_required")
	}
	if user == nil {
		return response{}, refuse("no_session")
	}
	now := b.clock().Unix()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	if req.path == panelStatusPath {
		online := b.lastPull >= 0 && now-b.lastPull < panelOnlineWindow
		return jsonAnswer(200, map[string]any{"enabled": b.panelFor(user), "team_online": online}), nil
	}
	if !b.panelFor(user) {
		return response{}, refuse("not_found")
	}
	if strings.HasPrefix(req.path, panelQuestionPrefix) {
		q := b.questions[req.path[len(panelQuestionPrefix):]]
		if q == nil || q.User.ID != user.ID {
			return response{}, refuse("not_found")
		}
		out := map[string]any{"id": q.ID, "status": q.Status, "text": q.Text, "asked_at": q.AskedAt}
		if q.Answer != nil {
			out["answer"], out["by"] = *q.Answer, q.By
		}
		return jsonAnswer(200, out), nil
	}
	if req.oversize || len(req.body) > MaxBody {
		return response{}, refuse("too_large")
	}
	value, err := parseJSON(req.body)
	data, ok := value.(map[string]any)
	if err != nil || !ok {
		return response{}, refuse("bad_params")
	}
	text, ok := data["text"].(string)
	if !ok || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > panelTextMax {
		return response{}, refuse("bad_params")
	}
	var page map[string]string
	for key, v := range data {
		if key == "text" {
			continue
		}
		if key != "page" {
			return response{}, refuse("bad_params")
		}
		raw, ok := v.(map[string]any)
		if !ok {
			return response{}, refuse("bad_params")
		}
		page = map[string]string{}
		for k, pv := range raw {
			s, ok := pv.(string)
			limit := map[string]int{"path": 300, "record_id": 120}[k]
			if !ok || limit == 0 || utf8.RuneCountInString(s) > limit {
				return response{}, refuse("bad_params")
			}
			page[k] = textControl.ReplaceAllString(s, "")
		}
	}
	var asked []int64
	for _, t := range b.asked[user.ID] {
		if t > now-3600 {
			asked = append(asked, t)
		}
	}
	if int64(len(asked)) >= b.rate["panel_per_user_hour"] {
		return response{}, refuse("rate_limited")
	}
	open := 0
	for _, q := range b.questions {
		if q.open() {
			open++
		}
	}
	if open >= panelOpenMax {
		return response{}, refuse("busy")
	}
	b.asked[user.ID] = append(asked, now)
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return response{}, refuse("busy")
	}
	id := "q_" + b64u(random)
	b.questions[id] = &question{ID: id, User: *user, Text: textControl.ReplaceAllString(strings.TrimSpace(text), ""),
		Page: page, AskedAt: now, Status: "waiting", UpdatedAt: now}
	b.order = append(b.order, id)
	return jsonAnswer(200, map[string]any{"question_id": id}), nil
}

// sweep expires old questions; when the team has not pulled for 2 minutes, it answers the open ones "unavailable".
func (b *Bridge) sweep(now int64) {
	kept := b.order[:0]
	for _, id := range b.order {
		if q := b.questions[id]; q != nil && q.AskedAt+panelExpiry > now {
			kept = append(kept, id)
		} else {
			delete(b.questions, id)
		}
	}
	b.order = kept
	for id, asked := range b.asked {
		if len(asked) == 0 || asked[len(asked)-1] <= now-3600 {
			delete(b.asked, id)
		}
	}
	if b.lastPull >= 0 && now-b.lastPull < panelOfflineAnswer {
		return
	}
	last := b.lastPull
	if last < 0 {
		last = 0
	}
	for _, q := range b.questions {
		since := q.UpdatedAt
		if last > since {
			since = last
		}
		if q.open() && now-since >= panelOfflineAnswer {
			text := panelUnavailable
			q.Status, q.Answer, q.By, q.UpdatedAt = "unavailable", &text, "Atrium", now
		}
	}
}

func (b *Bridge) pullQuestions(now int64) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastPull = now
	b.sweep(now)
	out := []map[string]any{}
	for _, id := range b.order {
		q := b.questions[id]
		if q.Status == "waiting" && len(out) < panelPullMax {
			q.Status, q.UpdatedAt = "answering", now
			var page any
			if q.Page != nil {
				page = q.Page
			}
			out = append(out, map[string]any{"id": q.ID, "text": q.Text, "tool_user": q.User, "page": page,
				"asked_at": q.AskedAt})
		}
	}
	return out
}

func (b *Bridge) panelAnswer(params map[string]any, now int64) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.questions[params["question_id"].(string)]
	if q == nil || !q.open() {
		return map[string]any{"ok": false}
	}
	status := params["status"].(string)
	if status == "working" {
		status = "answering"
	}
	text := textControl.ReplaceAllString(params["text"].(string), "")
	by, _ := params["by"].(string)
	q.Status, q.Answer, q.By, q.UpdatedAt = status, &text, textControl.ReplaceAllString(by, ""), now
	return map[string]any{"ok": true}
}

// ---- events ----

// Emit queues an event declared in atrium-bridge.json; it never blocks and is false when the event was not queued
// (undeclared name, a payload over 16 KiB, or a full outbox - counted in atrium.ping's drops).
func (b *Bridge) Emit(name string, payload map[string]any) bool {
	return b.EmitContext(context.Background(), name, payload)
}

// EmitContext is Emit from a handler's context: the event then carries cause {"jti"} of a granted call.
func (b *Bridge) EmitContext(ctx context.Context, name string, payload map[string]any) bool {
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := json.Marshal(payload)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil || !b.Ready() || !b.eventNames[name] || len(raw) > eventPayloadMax {
		b.rejected++
		return false
	}
	now := b.clock().Unix()
	for len(b.events) > 0 && b.events[0].At <= now-outboxTTL {
		b.events = b.events[1:]
	}
	if len(b.events) >= outboxMax {
		b.drops++
		return false
	}
	b.seq++
	e := event{Seq: b.seq, Name: name, Payload: raw, At: now}
	if ctx != nil {
		if jti, ok := ctx.Value(causeKey{}).(string); ok && jti != "" {
			e.Cause = map[string]string{"jti": jti}
		}
	}
	b.events = append(b.events, e)
	return true
}

func (b *Bridge) pullEvents(after, now int64) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	if after > b.seq { // the bridge restarted since: deliver from the start
		after = 0
	}
	for len(b.events) > 0 && (b.events[0].Seq <= after || b.events[0].At <= now-outboxTTL) {
		b.events = b.events[1:]
	}
	n := len(b.events)
	if n > eventsPullMax {
		n = eventsPullMax
	}
	out := append([]event{}, b.events[:n]...)
	next := after
	if n > 0 {
		next = out[n-1].Seq
	}
	return map[string]any{"events": out, "next": next}
}

// Emit queues an event on the bridge created last (atriumbridge.Emit); false when there is none.
func Emit(name string, payload map[string]any) bool {
	return EmitContext(context.Background(), name, payload)
}

// EmitContext is Emit from a handler's context (granted calls set the event's cause).
func EmitContext(ctx context.Context, name string, payload map[string]any) bool {
	defaultMu.Lock()
	b := defaultBridge
	defaultMu.Unlock()
	return b != nil && b.EmitContext(ctx, name, payload)
}

// ---- helpers ----

func oneOf(value string, options ...string) bool {
	for _, o := range options {
		if value == o {
			return true
		}
	}
	return false
}

func truncate(text string, n int) string {
	runes := []rune(text)
	if len(runes) > n {
		return string(runes[:n])
	}
	return text
}

func copyRate(rate map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(rate))
	for k, v := range rate {
		out[k] = v
	}
	return out
}
