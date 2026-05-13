package router

import "strings"

// Router performs O(1) SNI → backend lookup using two hash maps.
type Router struct {
	exact    map[string]string
	wildcard map[string]string
	def      string
}

// New creates a Router. routes maps backend address → list of SNI patterns.
// Patterns starting with "*." are wildcards; the rest are exact.
func New(routes map[string][]string, defaultBackend string) *Router {
	r := &Router{
		exact:    make(map[string]string),
		wildcard: make(map[string]string),
		def:      defaultBackend,
	}
	for backend, patterns := range routes {
		for _, p := range patterns {
			if strings.HasPrefix(p, "*.") {
				domain := p[2:] // strip "*."
				r.wildcard[domain] = backend
			} else {
				r.exact[p] = backend
			}
		}
	}
	return r
}

// Lookup resolves an SNI hostname to a backend address.
// O(1): two map lookups max, then default.
func (r *Router) Lookup(sni string) string {
	if b, ok := r.exact[sni]; ok {
		return b
	}
	if idx := strings.IndexByte(sni, '.'); idx != -1 {
		domain := sni[idx+1:]
		if b, ok := r.wildcard[domain]; ok {
			return b
		}
	}
	return r.def
}
