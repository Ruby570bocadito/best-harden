package surface

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// netfilter es el cortafuegos del kernel de Linux (nftables o iptables),
// reducido a lo que decide si una conexión nueva llega a un puerto local:
// las cadenas base del gancho input y las que estas llaman. ufw y firewalld
// generan reglas de nftables o iptables, así que se evalúan igual.
type netfilter struct {
	bases  []nfBase
	chains map[string]*nfChain // clave: familia/tabla/cadena
	// uncovered son cadenas que pueden descartar tráfico antes de la
	// entrada (prerouting, ingress, tablas raw/mangle) y que no se evalúan:
	// un puerto puede aparecer accesible sin estarlo.
	uncovered []string
}

// nfBase es una cadena base del gancho input.
type nfBase struct {
	family string // inet, ip o ip6
	policy string // accept o drop
	chain  *nfChain
}

type nfChain struct {
	name  string
	rules []nfRule
}

type portRange struct{ lo, hi int }

// nfRule es una regla con sus condiciones ya interpretadas.
type nfRule struct {
	ref      string // cómo se nombra: su comentario o «cadena #n»
	proto    string // "" cualquiera, tcp, udp, th (tcp o udp), other
	ports    []portRange
	portsNeg bool
	family   string   // "" cualquiera, ip o ip6
	limits   []string // restricciones de origen: direcciones, interfaz, puerto de origen
	dst      string   // direcciones de destino (como en Windows, las locales)
	skip     bool     // no se aplica a una conexión nueva a un puerto local
	unknown  bool     // tiene condiciones que no se evalúan
	// flags indica que la regla mira los flags TCP (--syn, --tcp-flags,
	// "tcp flags & …"): solo afecta a ciertos paquetes. Un bloqueo con esa
	// condición (anti escaneo) no impide una conexión normal; un permiso
	// sí la deja pasar (el SYN que la abre).
	flags   bool
	verdict string // accept, drop, jump, goto, return o "" (sigue)
	target  string // clave de la cadena de jump/goto
}

// nfResult es el resultado de recorrer una cadena.
type nfResult struct {
	verdict    string   // accept, drop o return (llega al final)
	limits     []string // desde dónde se acepta, si solo es desde ciertos orígenes
	limitRules []string
	rule       string // la regla que aceptó o bloqueó
}

// policy resume la acción por defecto de la entrada: drop si alguna cadena
// base descarta lo que no permite una regla.
func (nf *netfilter) policy() string {
	if len(nf.bases) == 0 {
		return ""
	}
	for _, b := range nf.bases {
		if b.policy == "drop" {
			return "drop"
		}
	}
	return "accept"
}

// ruleCount cuenta las reglas alcanzables desde las cadenas de entrada.
func (nf *netfilter) ruleCount() int {
	seen := map[*nfChain]bool{}
	var walk func(c *nfChain) int
	walk = func(c *nfChain) int {
		if c == nil || seen[c] {
			return 0
		}
		seen[c] = true
		n := len(c.rules)
		for _, r := range c.rules {
			if r.target != "" {
				n += walk(nf.chains[r.target])
			}
		}
		return n
	}
	n := 0
	for _, b := range nf.bases {
		n += walk(b.chain)
	}
	return n
}

// evaluate decide desde dónde llega una conexión nueva al puerto. Como en
// Windows, se peca de considerar el puerto accesible: un bloqueo con
// condiciones que no se pueden evaluar no cuenta.
func (nf *netfilter) evaluate(p Port) Access {
	if strings.EqualFold(p.Process, "docker-proxy") {
		return Access{State: FirewallOpen, Why: "Docker publica el puerto con DNAT: el tráfico no pasa por la cadena input del firewall"}
	}
	if len(nf.bases) == 0 {
		return Access{State: FirewallOpen, Why: "el firewall no tiene reglas de entrada"}
	}
	rank := map[string]int{FirewallOpen: 0, FirewallLimited: 1, FirewallFiltered: 2}
	var best *Access
	for _, fam := range portFamilies(p) {
		// En cada familia, todas las cadenas base deben aceptar: gana la
		// más restrictiva.
		var worst *Access
		for _, b := range nf.bases {
			if b.family != "inet" && b.family != fam {
				continue
			}
			res := nf.run(b.chain, p, fam, 0)
			a := res.access(b)
			if worst == nil || rank[a.State] > rank[worst.State] {
				worst = &a
			} else if a.State == FirewallLimited && worst.State == FirewallLimited {
				for _, x := range a.Limits {
					worst.Limits = appendOnce(worst.Limits, x)
				}
				for _, x := range a.Rules {
					worst.Rules = appendOnce(worst.Rules, x)
				}
			}
		}
		if worst == nil {
			worst = &Access{State: FirewallOpen, Why: "el firewall no tiene reglas de entrada para " + famName(fam)}
		}
		// Entre familias (IPv4, IPv6) gana la menos restrictiva.
		if best == nil || rank[worst.State] < rank[best.State] {
			best = worst
		}
	}
	if best.State == FirewallLimited {
		sortLimits(best.Limits)
		best.Limit = joinHuman(best.Limits)
		best.Why = limitedWhy(best.Limit, best.Rules)
	}
	return *best
}

func (res nfResult) access(b nfBase) Access {
	switch {
	case res.verdict == "accept":
		return Access{State: FirewallOpen, Why: "lo permite la regla " + res.rule, Rules: []string{res.rule}}
	case res.verdict == "return" && b.policy != "drop":
		return Access{State: FirewallOpen, Why: fmt.Sprintf("ninguna regla lo bloquea y la cadena %s acepta por defecto", b.chain.name)}
	case len(res.limits) > 0:
		return Access{State: FirewallLimited, Limits: res.limits, Rules: res.limitRules}
	case res.verdict == "drop":
		return Access{State: FirewallFiltered, Why: "lo bloquea la regla " + res.rule}
	}
	return Access{State: FirewallFiltered, Why: fmt.Sprintf("ninguna regla lo permite (la cadena %s descarta por defecto)", b.chain.name)}
}

func famName(f string) string {
	if f == "ip6" {
		return "IPv6"
	}
	return "IPv4"
}

// portFamilies devuelve las familias por las que llega tráfico al puerto.
// En Linux, un socket en :: también acepta IPv4 (salvo bindv6only).
func portFamilies(p Port) []string {
	var v4, v6 bool
	for _, a := range p.Addresses {
		a = strings.Trim(a, "[]")
		if i := strings.IndexByte(a, '%'); i >= 0 {
			a = a[:i]
		}
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
			v4, v6 = true, true
		case ip.To4() != nil:
			v4 = true
		default:
			v6 = true
			if ip.IsUnspecified() {
				v4 = true
			}
		}
	}
	var out []string
	if v4 || !v6 {
		out = append(out, "ip")
	}
	if v6 {
		out = append(out, "ip6")
	}
	return out
}

// run recorre una cadena para una conexión nueva al puerto p.
func (nf *netfilter) run(c *nfChain, p Port, fam string, depth int) nfResult {
	var res nfResult
	if c == nil || depth > 16 {
		res.verdict = "return"
		return res
	}
	// Tras un return con condiciones, lo que sigue solo afecta a parte del
	// tráfico: sus bloqueos ya no se dan por seguros.
	partial := false
	for i := range c.rules {
		r := &c.rules[i]
		if !r.applies(p, fam) {
			continue
		}
		labels := r.labels()
		restricted := len(labels) > 0
		switch r.verdict {
		case "accept":
			if !restricted {
				res.verdict, res.rule = "accept", r.ref
				return res
			}
			res.addLimits(labels, r.ref)
		case "drop":
			if restricted || partial || r.flags {
				continue
			}
			res.verdict, res.rule = "drop", r.ref
			return res
		case "jump", "goto":
			sub := nf.run(nf.chains[r.target], p, fam, depth+1)
			if r.flags && sub.verdict == "drop" {
				// Solo ciertos paquetes (anti escaneo) van a parar a un bloqueo.
				continue
			}
			if restricted {
				// Solo para parte del tráfico (una interfaz, unos orígenes). Si
				// la subcadena a su vez solo acepta desde ciertos orígenes, esos
				// son los que cuentan: son más concretos.
				switch {
				case sub.verdict == "accept":
					res.addLimits(labels, sub.rule)
				case len(sub.limits) > 0:
					for _, x := range sub.limits {
						res.limits = appendOnce(res.limits, x)
					}
					for _, x := range sub.limitRules {
						res.limitRules = appendOnce(res.limitRules, x)
					}
				}
				// Con goto, ese tráfico ya no vuelve a esta cadena.
				partial = partial || r.verdict == "goto"
				continue
			}
			if sub.verdict == "accept" {
				return sub
			}
			if sub.verdict == "drop" && partial {
				continue
			}
			for _, x := range sub.limits {
				res.limits = appendOnce(res.limits, x)
			}
			for _, x := range sub.limitRules {
				res.limitRules = appendOnce(res.limitRules, x)
			}
			if sub.verdict == "drop" {
				res.verdict, res.rule = "drop", sub.rule
				return res
			}
			if r.verdict == "goto" {
				res.verdict = "return"
				return res
			}
		case "return":
			if restricted || r.flags {
				partial = true
				continue
			}
			res.verdict = "return"
			return res
		}
	}
	res.verdict = "return"
	return res
}

func (res *nfResult) addLimits(labels []string, rule string) {
	for _, x := range labels {
		res.limits = appendOnce(res.limits, x)
	}
	res.limitRules = appendOnce(res.limitRules, rule)
}

// applies indica si la regla puede aplicarse a una conexión nueva al puerto.
func (r *nfRule) applies(p Port, fam string) bool {
	if r.skip || (r.family != "" && r.family != fam) {
		return false
	}
	switch r.proto {
	case "", "th":
	case "tcp", "udp":
		if r.proto != p.Proto {
			return false
		}
	default:
		return false
	}
	if r.ports != nil {
		in := false
		for _, pr := range r.ports {
			if p.Port >= pr.lo && p.Port <= pr.hi {
				in = true
				break
			}
		}
		if in == r.portsNeg {
			return false
		}
	}
	if r.dst != "" {
		// Una regla limitada a ciertas direcciones de destino no cubre un
		// puerto que solo escucha en otras.
		if specific := specificAddrs(p.Addresses); len(specific) > 0 && !parseAddrs(r.dst).containsAny(specific) {
			return false
		}
	}
	return true
}

// labels devuelve las restricciones de la regla (vacío si no tiene).
func (r *nfRule) labels() []string {
	out := append([]string(nil), r.limits...)
	if r.dst != "" {
		out = append(out, parseAddrs(r.dst).describe(true)...)
	}
	if r.unknown {
		out = append(out, "con condiciones que Adarve no evalúa")
	}
	return out
}

// ifaceLabel nombra una interfaz de red como restricción.
func ifaceLabel(names []string) string {
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "tailscale") {
			return "Tailscale"
		}
		out = append(out, n)
	}
	return "en la interfaz " + strings.Join(out, ", ")
}

// ---- nftables (nft -j list ruleset) -----------------------------------------

// parseNftJSON interpreta la salida de "nft -j list ruleset". skipTables
// excluye tablas (familia/nombre) que se leen mejor con iptables-save.
func parseNftJSON(data []byte, skipTables map[string]bool) (*netfilter, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("salida de nft no válida: %w", err)
	}
	type chainObj struct {
		Family, Table, Name, Hook, Type, Policy string
	}
	type ruleObj struct {
		Family, Table, Chain, Comment string
		Handle                        int
		Expr                          []map[string]json.RawMessage
	}
	type setObj struct {
		Family, Table, Name string
		Elem                []json.RawMessage
	}
	nf := &netfilter{chains: map[string]*nfChain{}}
	sets := map[string][]string{}
	var chains []chainObj
	var rules []ruleObj
	for _, item := range doc.Nftables {
		for kind, raw := range item {
			switch kind {
			case "chain":
				var c chainObj
				if json.Unmarshal(raw, &c) == nil {
					chains = append(chains, c)
				}
			case "rule":
				var r ruleObj
				if json.Unmarshal(raw, &r) == nil {
					rules = append(rules, r)
				}
			case "set":
				var s setObj
				if json.Unmarshal(raw, &s) == nil {
					var vals []string
					for _, e := range s.Elem {
						vals = append(vals, nftValues(e)...)
					}
					sets[s.Family+"/"+s.Table+"/"+s.Name] = vals
				}
			}
		}
	}
	key := func(fam, table, name string) string { return fam + "/" + table + "/" + name }
	pre := map[string]bool{} // cadenas de prerouting/ingress → política drop
	for _, c := range chains {
		if skipTables[c.Family+"/"+c.Table] {
			continue
		}
		ch := &nfChain{name: c.Name}
		nf.chains[key(c.Family, c.Table, c.Name)] = ch
		if c.Hook == "input" && (c.Type == "" || c.Type == "filter") && (c.Family == "inet" || c.Family == "ip" || c.Family == "ip6") {
			pol := "accept"
			if c.Policy == "drop" {
				pol = "drop"
			}
			nf.bases = append(nf.bases, nfBase{family: c.Family, policy: pol, chain: ch})
		}
		if (c.Hook == "prerouting" || c.Hook == "ingress") && (c.Type == "" || c.Type == "filter") {
			pre[key(c.Family, c.Table, c.Name)] = c.Policy == "drop"
		}
	}
	count := map[string]int{}
	for _, r := range rules {
		ch := nf.chains[key(r.Family, r.Table, r.Chain)]
		if ch == nil {
			continue
		}
		ck := key(r.Family, r.Table, r.Chain)
		count[ck]++
		rule := nfRule{ref: fmt.Sprintf("«%s #%d»", r.Chain, count[ck])}
		if r.Comment != "" {
			rule.ref = "«" + r.Comment + "»"
		}
		for _, e := range r.Expr {
			nftExpr(&rule, e, func(name string) ([]string, bool) {
				v, ok := sets[key(r.Family, r.Table, name)]
				return v, ok
			})
			if rule.target != "" && !strings.Contains(rule.target, "/") {
				rule.target = key(r.Family, r.Table, rule.target)
			}
		}
		if r.Family == "ip" || r.Family == "ip6" {
			rule.family = firstNonEmpty(rule.family, r.Family)
		}
		ch.rules = append(ch.rules, rule)
	}
	// Cadenas anteriores a la entrada que descartan tráfico: no se evalúan
	// (salvo las antisuplantación con fib, que son condiciones desconocidas).
	for k, drop := range pre {
		for _, r := range nf.chains[k].rules {
			drop = drop || (r.verdict == "drop" && !r.skip && !r.unknown)
		}
		if drop {
			nf.uncovered = appendOnce(nf.uncovered, "nft "+k)
		}
	}
	sort.Strings(nf.uncovered)
	return nf, nil
}

// nftExpr incorpora a la regla una expresión de nft.
func nftExpr(r *nfRule, e map[string]json.RawMessage, set func(string) ([]string, bool)) {
	for kind, raw := range e {
		switch kind {
		case "accept", "drop", "return":
			r.verdict = kind
		case "reject":
			r.verdict = "drop"
		case "jump", "goto":
			var t struct{ Target string }
			if json.Unmarshal(raw, &t) == nil {
				r.verdict, r.target = kind, t.Target
			}
		case "counter", "log", "notrack", "meta", "mangle", "quota", "ct":
			// Sentencias sin efecto en la decisión (meta/ct como asignación).
		case "limit":
			var l struct{ Inv bool }
			if json.Unmarshal(raw, &l) == nil && l.Inv {
				r.unknown = true // "limit rate over": solo parte del tráfico
			}
		case "xt":
			var x struct{ Name string }
			_ = json.Unmarshal(raw, &x)
			switch x.Name {
			case "comment", "tcp", "udp", "limit":
			case "conntrack", "state":
				// iptables-nft no traduce el estado: casi siempre es
				// ESTABLISHED,RELATED o INVALID.
				r.skip = true
			case "icmp", "icmp6":
				r.proto = "other"
			default:
				r.unknown = true
			}
		case "match":
			var m struct {
				Op    string
				Left  map[string]json.RawMessage
				Right json.RawMessage
			}
			if json.Unmarshal(raw, &m) != nil {
				r.unknown = true
				continue
			}
			nftMatch(r, m.Op, m.Left, m.Right, set)
		default:
			r.unknown = true // queue, socket, tproxy…
		}
	}
}

func nftMatch(r *nfRule, op string, left map[string]json.RawMessage, right json.RawMessage, set func(string) ([]string, bool)) {
	pos := op == "==" || op == "in" || op == ""
	vals := nftValues(right)
	if len(vals) == 1 && strings.HasPrefix(vals[0], "@") {
		if v, ok := set(vals[0][1:]); ok && len(v) > 0 {
			vals = v
		}
	}
	for kind, raw := range left {
		switch kind {
		case "payload":
			var pl struct{ Protocol, Field string }
			if json.Unmarshal(raw, &pl) != nil || pl.Protocol == "" {
				r.unknown = true
				return
			}
			nftPayload(r, pl.Protocol, pl.Field, op, pos, vals)
		case "meta":
			var mk struct{ Key string }
			_ = json.Unmarshal(raw, &mk)
			switch mk.Key {
			case "l4proto":
				if pos {
					setProto(r, vals)
				} else {
					r.unknown = true
				}
			case "iifname", "iif":
				switch {
				case pos && len(vals) == 1 && vals[0] == "lo":
					r.skip = true // solo el propio equipo
				case pos:
					r.limits = append(r.limits, ifaceLabel(vals))
				case containsFold(vals, "lo"):
					// "!= lo": todo lo que llega de la red
				default:
					r.unknown = true
				}
			case "nfproto":
				if pos && len(vals) == 1 {
					r.family = map[string]string{"ipv4": "ip", "ipv6": "ip6"}[vals[0]]
				}
			case "pkttype":
				if !(pos && len(vals) == 1 && vals[0] == "host") {
					r.skip = true // difusión o multidifusión, no una conexión
				}
			case "oif", "oifname", "skuid", "skgid", "cpu", "length", "protocol":
			default:
				r.unknown = true // mark, priority…
			}
		case "ct":
			var ck struct{ Key string }
			_ = json.Unmarshal(raw, &ck)
			switch ck.Key {
			case "state":
				isNew := containsFold(vals, "new") || containsFold(vals, "untracked")
				if pos != isNew {
					r.skip = true // solo conexiones ya establecidas o inválidas
				}
			case "status":
				if pos && containsFold(vals, "dnat") {
					r.skip = true // solo tráfico redirigido (DNAT)
				} else {
					r.unknown = true
				}
			default:
				r.unknown = true
			}
		case "fib":
			switch {
			case containsFold(vals, "local") && pos:
			case pos && (containsFold(vals, "multicast") || containsFold(vals, "broadcast")):
				r.skip = true
			default:
				r.unknown = true // fib saddr . iif oif missing (antisuplantación)
			}
		case "&", "|", "^":
			// tcp flags & (…) == syn: solo ciertos paquetes (ver flags).
			r.flags = true
		default:
			r.unknown = true
		}
	}
}

func nftPayload(r *nfRule, proto, field, op string, pos bool, vals []string) {
	switch {
	case field == "dport" && (proto == "tcp" || proto == "udp" || proto == "th"):
		mergeProto(r, proto)
		ports, ok := parsePorts(vals, op)
		if !ok {
			r.unknown = true
			return
		}
		r.ports, r.portsNeg = ports, op == "!="
	case field == "sport" && (proto == "tcp" || proto == "udp" || proto == "th"):
		mergeProto(r, proto)
		if pos {
			r.limits = append(r.limits, "desde el puerto de origen "+strings.Join(vals, ", "))
		} else {
			r.unknown = true
		}
	case (proto == "ip" || proto == "ip6") && field == "saddr":
		r.family = proto
		if pos {
			r.limits = append(r.limits, parseAddrs(strings.Join(vals, ",")).describe(false)...)
		} else {
			r.unknown = true
		}
	case (proto == "ip" || proto == "ip6") && field == "daddr":
		r.family = proto
		if pos {
			r.dst = strings.Join(vals, ",")
		} else {
			r.unknown = true
		}
	case proto == "ip" && field == "protocol", proto == "ip6" && field == "nexthdr":
		r.family = proto
		if pos {
			setProto(r, vals)
		} else {
			r.unknown = true
		}
	case proto == "tcp" || proto == "udp":
		mergeProto(r, proto) // tcp flags…
	case proto == "icmp" || proto == "icmpv6" || proto == "sctp" || proto == "esp" || proto == "ah":
		r.proto = "other"
	case proto == "ip" || proto == "ip6" || proto == "ether" || proto == "vlan":
		// Otros campos de la cabecera (ttl, dscp…)
	default:
		r.unknown = true
	}
}

// setProto aplica "meta l4proto" o "ip protocol" con uno o varios valores.
func setProto(r *nfRule, vals []string) {
	tcp, udp := containsFold(vals, "tcp") || containsFold(vals, "6"), containsFold(vals, "udp") || containsFold(vals, "17")
	switch {
	case tcp && udp:
		mergeProto(r, "th")
	case tcp:
		mergeProto(r, "tcp")
	case udp:
		mergeProto(r, "udp")
	default:
		r.proto = "other"
	}
}

func mergeProto(r *nfRule, p string) {
	switch {
	case r.proto == "other":
	case r.proto == "" || r.proto == "th":
		r.proto = p
	case p != "th" && p != r.proto:
		r.proto = "other" // tcp y udp a la vez: imposible
	}
}

// parsePorts interpreta puertos sueltos, rangos ("8000-8010") y
// comparaciones (">= 1024").
func parsePorts(vals []string, op string) ([]portRange, bool) {
	var out []portRange
	for _, v := range vals {
		lo, hi, isRange := strings.Cut(v, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 != nil || err2 != nil {
			return nil, false
		}
		out = append(out, portRange{a, b})
	}
	if len(out) != 1 {
		return out, len(out) > 0
	}
	switch op {
	case ">=":
		out[0].hi = 65535
	case ">":
		out[0] = portRange{out[0].lo + 1, 65535}
	case "<=":
		out[0].lo = 0
	case "<":
		out[0] = portRange{0, out[0].hi - 1}
	}
	return out, true
}

// nftValues convierte un valor de nft JSON en texto: números, cadenas,
// conjuntos, rangos y prefijos.
func nftValues(raw json.RawMessage) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return flatten(v)
}

func flatten(v any) []string {
	switch x := v.(type) {
	case float64:
		return []string{strconv.Itoa(int(x))}
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, flatten(e)...)
		}
		return out
	case map[string]any:
		switch {
		case x["set"] != nil:
			return flatten(x["set"])
		case x["prefix"] != nil:
			if p, ok := x["prefix"].(map[string]any); ok {
				addr, n := flatten(p["addr"]), flatten(p["len"])
				if len(addr) == 1 && len(n) == 1 {
					return []string{addr[0] + "/" + n[0]}
				}
			}
		case x["range"] != nil:
			if r := flatten(x["range"]); len(r) == 2 {
				return []string{r[0] + "-" + r[1]}
			}
		case x["elem"] != nil:
			if el, ok := x["elem"].(map[string]any); ok {
				return flatten(el["val"])
			}
		}
	}
	return nil
}

// ---- iptables-save -----------------------------------------------------------

// parseIptablesSave añade al cortafuegos la tabla filter de la salida de
// iptables-save (family "ip") o ip6tables-save ("ip6").
func (nf *netfilter) parseIptablesSave(text, family string) {
	inFilter := false
	table := ""
	policies := map[string]string{}
	count := map[string]int{}
	key := func(name string) string { return family + "/iptables/" + name }
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
			inFilter = table == "filter"
		case (table == "raw" || table == "mangle") && (strings.HasPrefix(line, ":PREROUTING DROP") ||
			strings.HasPrefix(line, "-A PREROUTING ") && strings.Contains(line, " -j DROP")):
			// Descartes antes de la entrada que no se evalúan.
			nf.uncovered = appendOnce(nf.uncovered, family+"tables "+table+" PREROUTING")
		case !inFilter || line == "" || strings.HasPrefix(line, "#"):
		case line == "COMMIT":
			inFilter, table = false, ""
		case strings.HasPrefix(line, ":"):
			f := strings.Fields(line[1:])
			if len(f) >= 2 {
				nf.chains[key(f[0])] = &nfChain{name: f[0]}
				policies[f[0]] = strings.ToLower(f[1])
			}
		case strings.HasPrefix(line, "-A "):
			args := splitArgs(line[3:])
			if len(args) == 0 {
				continue
			}
			ch := nf.chains[key(args[0])]
			if ch == nil {
				continue
			}
			count[args[0]]++
			r := iptRule(args[1:], family)
			if r.ref == "" {
				r.ref = fmt.Sprintf("«%s #%d»", args[0], count[args[0]])
			}
			if r.target != "" {
				r.target = key(r.target)
			}
			ch.rules = append(ch.rules, r)
		}
	}
	if c := nf.chains[key("INPUT")]; c != nil {
		pol := "accept"
		if policies["INPUT"] == "drop" {
			pol = "drop"
		}
		nf.bases = append(nf.bases, nfBase{family: family, policy: pol, chain: c})
	}
}

// iptRule interpreta las opciones de una regla de iptables.
func iptRule(args []string, family string) nfRule {
	r := nfRule{family: family}
	neg := false
	next := func(i *int) string {
		if *i+1 < len(args) {
			*i++
			return args[*i]
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "!" {
			neg = true
			continue
		}
		switch a {
		case "-p", "--protocol":
			v := strings.ToLower(next(&i))
			switch {
			case neg:
				r.unknown = true
			case v == "all" || v == "0":
			default:
				setProto(&r, []string{v})
			}
		case "-s", "--source", "--src-range":
			v := next(&i)
			if neg {
				r.unknown = true
			} else {
				r.limits = append(r.limits, parseAddrs(v).describe(false)...)
			}
		case "-d", "--destination", "--dst-range":
			v := next(&i)
			if neg {
				r.unknown = true
			} else {
				r.dst = v
			}
		case "-i", "--in-interface":
			v := strings.TrimSuffix(next(&i), "+")
			switch {
			case neg && v == "lo":
			case neg:
				r.unknown = true
			case v == "lo":
				r.skip = true
			default:
				r.limits = append(r.limits, ifaceLabel([]string{v}))
			}
		case "-o", "--out-interface", "--log-prefix", "--log-level", "--reject-with", "--limit", "--limit-burst",
			"--icmp-type", "--icmpv6-type", "--mask", "--name", "--seconds", "--hitcount", "--tcp-flags":
			next(&i)
			if a == "--tcp-flags" {
				next(&i)
				r.flags = true
			}
		case "-m", "--match":
			switch m := next(&i); m {
			case "tcp", "udp", "comment", "limit", "multiport", "conntrack", "state", "addrtype", "iprange", "icmp", "icmp6":
			case "set":
				// Los nombres del ipset van en --match-set.
			default:
				r.unknown = true // recent, mark, owner…
			}
		case "--dport", "--destination-port", "--dports", "--destination-ports", "--ports":
			v := strings.ReplaceAll(next(&i), ":", "-")
			ports, ok := parsePorts(strings.Split(v, ","), "")
			if !ok {
				r.unknown = true
			} else {
				r.ports, r.portsNeg = ports, neg
			}
		case "--sport", "--source-port", "--sports", "--source-ports":
			v := next(&i)
			if neg {
				r.unknown = true
			} else {
				r.limits = append(r.limits, "desde el puerto de origen "+strings.ReplaceAll(v, ":", "-"))
			}
		case "--ctstate", "--state":
			v := strings.ToUpper(next(&i))
			isNew := strings.Contains(v, "NEW") || strings.Contains(v, "UNTRACKED")
			if isNew == neg {
				r.skip = true
			}
		case "--dst-type":
			v := strings.ToUpper(next(&i))
			switch {
			case neg:
				r.unknown = true
			case strings.Contains(v, "LOCAL"):
			default:
				r.skip = true // difusión o multidifusión
			}
		case "--syn":
			r.flags = true
		case "--src-type", "--set", "--update", "--rcheck", "--remove", "--rsource", "--rdest", "--limit-iface-in":
			if a == "--src-type" {
				next(&i)
				r.unknown = true
			}
		case "--match-set":
			name := next(&i)
			dir := next(&i)
			if neg || !strings.Contains(dir, "src") {
				r.unknown = true
			} else {
				r.limits = append(r.limits, "las direcciones del ipset "+name)
			}
		case "--comment":
			if c := strings.Trim(next(&i), `"'\`); c != "" {
				r.ref = "«" + c + "»"
			}
		case "-j", "--jump", "-g", "--goto":
			t := next(&i)
			switch t {
			case "ACCEPT":
				r.verdict = "accept"
			case "DROP", "REJECT":
				r.verdict = "drop"
			case "RETURN":
				r.verdict = "return"
			case "LOG", "NFLOG", "ULOG", "AUDIT", "MARK", "CONNMARK", "CT", "TRACE", "NFQUEUE":
			default:
				r.verdict, r.target = "jump", t
				if a == "-g" || a == "--goto" {
					r.verdict = "goto"
				}
			}
		default:
			if strings.HasPrefix(a, "-") {
				r.unknown = true
			}
		}
		neg = false
	}
	return r
}

// splitArgs separa los argumentos de una línea de iptables-save respetando
// las comillas de los comentarios.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && quote:
			i++
			cur.WriteByte(s[i])
		case c == '"':
			quote = !quote
		case c == ' ' && !quote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// iptablesManagedTables devuelve las tablas de nftables que gestiona
// iptables-nft (las mismas que muestra iptables-save, con más detalle).
func iptablesManagedTables(save4, save6 string) map[string]bool {
	out := map[string]bool{}
	for fam, save := range map[string]string{"ip": save4, "ip6": save6} {
		if !strings.Contains(firstLine(save), "nf_tables") {
			continue
		}
		for _, line := range strings.Split(save, "\n") {
			if strings.HasPrefix(line, "*") {
				out[fam+"/"+strings.TrimPrefix(strings.TrimSpace(line), "*")] = true
			}
		}
	}
	return out
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

// newLinuxFirewall une nftables e iptables en la vista del firewall.
func newLinuxFirewall(nft []byte, save4, save6 string) (*Firewall, error) {
	nf := &netfilter{chains: map[string]*nfChain{}}
	var sources []string
	if len(nft) > 0 {
		parsed, err := parseNftJSON(nft, iptablesManagedTables(save4, save6))
		if err != nil {
			return nil, err
		}
		nf = parsed
		if len(nf.bases) > 0 {
			sources = append(sources, "nftables")
		}
	}
	before := len(nf.bases)
	if save4 != "" {
		nf.parseIptablesSave(save4, "ip")
	}
	if save6 != "" {
		nf.parseIptablesSave(save6, "ip6")
	}
	if len(nf.bases) > before {
		sources = append(sources, "iptables")
	}
	sort.SliceStable(nf.bases, func(i, j int) bool { return nf.bases[i].family < nf.bases[j].family })
	src := strings.Join(sources, "+")
	if src == "" {
		src = "nftables"
	}
	return &Firewall{Profiles: []FirewallProfile{}, Source: src, InputPolicy: nf.policy(), InboundRules: nf.ruleCount(), nf: nf}, nil
}
