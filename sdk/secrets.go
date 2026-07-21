package hokora

// Secrets holds fetched secret values in memory.
//
// Values are stored as byte slices so that Zero can overwrite them. Secrets
// is not safe for concurrent modification, but concurrent reads are fine once
// fetching has returned it.
type Secrets struct {
	values map[string][]byte
}

// newSecrets copies the decoded values into a Secrets, holding each as its
// own byte slice.
func newSecrets(values map[string]string) *Secrets {
	m := make(map[string][]byte, len(values))
	for k, v := range values {
		m[k] = []byte(v)
	}
	return &Secrets{values: m}
}

// Get returns the value for key.
//
// The returned slice aliases the internal storage; do not modify it, and do
// not retain it past a call to Zero. ok is false when the key is absent.
func (s *Secrets) Get(key string) (value []byte, ok bool) {
	v, ok := s.values[key]
	return v, ok
}

// GetString returns the value for key as a string.
//
// Go strings are immutable, so a value obtained through this method cannot be
// overwritten by Zero and may outlive it. Prefer Get when the value's
// lifetime in memory matters.
func (s *Secrets) GetString(key string) (value string, ok bool) {
	v, ok := s.values[key]
	if !ok {
		return "", false
	}
	return string(v), true
}

// MustGetString returns the value for key and panics if it is absent.
//
// It is meant for application startup, where a missing secret should stop the
// program immediately rather than surface later as a nil value.
func (s *Secrets) MustGetString(key string) string {
	v, ok := s.GetString(key)
	if !ok {
		panic("hokora: secret " + key + " is not present")
	}
	return v
}

// Keys returns the names of the fetched secrets. The order is unspecified.
func (s *Secrets) Keys() []string {
	keys := make([]string, 0, len(s.values))
	for k := range s.values {
		keys = append(keys, k)
	}
	return keys
}

// Len reports how many secrets were fetched.
func (s *Secrets) Len() int { return len(s.values) }

// Zero overwrites the stored secret values and drops them.
//
// This is best-effort. Values already returned by GetString cannot be zeroed
// because Go strings are immutable, and the Go runtime may have retained
// copies made while garbage collecting. Zero also cannot undo a value that
// your program has copied elsewhere. See the package's Security section.
//
// After Zero, Get and GetString report every key as absent.
func (s *Secrets) Zero() {
	for k, v := range s.values {
		zero(v)
		delete(s.values, k)
	}
}

// zero overwrites b with zeroes. It is the SDK's local, dependency-free
// equivalent of the server's Zero; the same best-effort caveats apply.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
