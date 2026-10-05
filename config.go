package samba

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// TOML configuration and the resolved server context.
//
// Unknown keys are rejected so a typo in a config file fails loudly instead of
// silently taking a default. Like the original, `Config` is the parsed file and
// `Srv` is the immutable context handed to every worker.

// Config is the parsed server configuration.
type Config struct {
	Listen string `toml:"listen"`
	// Workers is the number of SO_REUSEPORT listener goroutines. 0 = one per
	// CPU core.
	Workers    int    `toml:"workers"`
	ServerName string `toml:"server_name"`
	// LogLevel: 0 = warn, 1 = info, 2 = debug.
	LogLevel uint8 `toml:"log_level"`
	// AllowGuest permits unauthenticated guest sessions. Defaults to true when
	// no [[user]] entries exist, false otherwise.
	AllowGuest *bool `toml:"allow_guest"`
	// RequireSigning rejects unsigned requests on authenticated sessions.
	RequireSigning bool `toml:"require_signing"`
	// Multichannel advertises SMB3 multichannel and accepts session binding so a
	// single client can stripe one share across multiple connections.
	Multichannel bool `toml:"multichannel"`
	// Encrypt requires SMB3 encryption (AES-128/256-GCM/CCM) for all post-auth
	// traffic. When false, client-initiated encryption (e.g. cifs `seal`) is
	// still honored if a cipher is negotiated.
	Encrypt bool `toml:"encrypt"`
	// AdvertiseOnly restricts multichannel interface advertisement to these
	// addresses. Empty = advertise every non-loopback interface.
	AdvertiseOnly []string `toml:"advertise_only"`
	// PreferAES256 picks AES-256 (GCM, then CCM) when offered, instead of
	// honoring the client's preference order.
	PreferAES256 bool `toml:"prefer_aes256"`
	// Oplocks grants read-caching (and, when asked, handle-caching) leases.
	Oplocks bool `toml:"oplocks"`
	// MaxConnections caps how many connections the server serves at once. It is
	// the main lever on worst-case memory use (see the tuning notes); a negative
	// value removes the limit.
	MaxConnections *int `toml:"max_connections"`
	// MinDialect is the oldest SMB dialect the server will negotiate, spelled as
	// in Dialect.Version ("2.0.2" through "3.1.1"). Empty means the default, and
	// is raised to 3.0 when Encrypt is set. A client that offers nothing at or
	// above the floor is refused rather than downgraded to a dialect the
	// operator excluded, which is what makes the floor a guarantee and not a
	// preference.
	MinDialect string `toml:"min_dialect"`
	// Shares and Users are the [ [share] ] / [ [user] ] tables.
	Shares []ShareCfg `toml:"share"`
	Users  []UserCfg  `toml:"user"`
}

// UserCfg is one `[[user]]` entry: a name plus exactly one of password or a
// precomputed NT hash (32 hex chars). The user database is how NTLMv2 logons are
// checked; there is no directory service behind it.
type UserCfg struct {
	Name     string `toml:"name"`
	Password string `toml:"password"`
	NTHash   string `toml:"nt_hash"`
}

// ShareCfg is one `[[share]]` entry.
type ShareCfg struct {
	Name     string `toml:"name"`
	Path     string `toml:"path"`
	ReadOnly bool   `toml:"read_only"`
}

// DefaultListen is the bind address used when `listen` is absent.
const DefaultListen = "0.0.0.0:445"

// DefaultServerName is the advertised server name used when `server_name` is absent.
const DefaultServerName = "SAMBA"

// newConfig returns a Config with every default filled in.
func newConfig() Config {
	maxConns := DefaultMaxConnections
	return Config{
		Listen:         DefaultListen,
		ServerName:     DefaultServerName,
		LogLevel:       LevelInfo,
		Oplocks:        true,
		MaxConnections: &maxConns,
	}
}

// LoadConfig reads, parses and validates a TOML config file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config %s: %w", path, err)
	}
	return ParseConfig(raw)
}

// ParseConfig parses and validates a TOML config document.
func ParseConfig(raw []byte) (*Config, error) {
	cfg := newConfig()
	md, err := toml.Decode(string(raw), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config parse error: unknown key(s): %s", strings.Join(keys, ", "))
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if _, err := c.ListenAddr(); err != nil {
		return err
	}
	if len(c.Shares) == 0 {
		return fmt.Errorf("config must define at least one [[share]]")
	}
	seen := make(map[string]bool, len(c.Shares))
	for _, s := range c.Shares {
		lower := strings.ToLower(s.Name)
		if s.Name == "" || strings.ContainsAny(s.Name, `\/`) {
			return fmt.Errorf("invalid share name %q", s.Name)
		}
		if seen[lower] {
			return fmt.Errorf("duplicate share name %q", s.Name)
		}
		seen[lower] = true
		if fi, err := os.Stat(s.Path); err != nil || !fi.IsDir() {
			return fmt.Errorf("share %q: path %q is not a directory", s.Name, s.Path)
		}
		if strings.EqualFold(s.Name, "IPC$") {
			return fmt.Errorf("share name IPC$ is reserved")
		}
	}
	seenUsers := make(map[string]bool, len(c.Users))
	for _, u := range c.Users {
		lower := strings.ToLower(u.Name)
		if u.Name == "" || seenUsers[lower] {
			return fmt.Errorf("invalid or duplicate user %q", u.Name)
		}
		seenUsers[lower] = true
		switch {
		case u.Password != "" && u.NTHash == "":
		case u.Password == "" && len(u.NTHash) == 32 && isHex(u.NTHash):
		default:
			return fmt.Errorf("user %q: set exactly one of password / nt_hash (32 hex chars)", u.Name)
		}
	}
	if c.MinDialect != "" {
		d, ok := DialectByName(c.MinDialect)
		if !ok {
			return fmt.Errorf("invalid min_dialect %q: want one of %s",
				c.MinDialect, strings.Join(DialectNames(), ", "))
		}
		// `encrypt = true` below SMB 3.0 is a contradiction, not a preference:
		// 2.x has no encryption at all, so such a server would negotiate a
		// cleartext session while claiming to require encryption. Refuse it
		// here rather than quietly raising the floor, so the operator's
		// explicit setting is never silently overridden.
		if c.Encrypt && d.Revision < dialectFloorOrPanic(EncryptionMinDialect).Revision {
			return fmt.Errorf("min_dialect = %q cannot be combined with encrypt = true: SMB 2.x has no encryption, so the server would serve those clients in the clear (set min_dialect = %q, or drop encrypt)",
				c.MinDialect, EncryptionMinDialect)
		}
	}
	return nil
}

// DialectFloor is the oldest dialect the server negotiates.
//
// It is `min_dialect` when set, and otherwise the default — raised to SMB 3.0
// when `encrypt` is set, because below 3.0 there is nothing to encrypt with.
// validate() rejects the case where those two disagree explicitly; this resolves
// the case where `min_dialect` was simply left out.
func (c *Config) DialectFloor() Dialect {
	if c.MinDialect != "" {
		if d, ok := DialectByName(c.MinDialect); ok {
			return d
		}
	}
	if c.Encrypt {
		return dialectFloorOrPanic(EncryptionMinDialect)
	}
	return dialectFloorOrPanic(DefaultMinDialect)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// UserDB resolves the user table to a lowercased-name → NT hash map.
func (c *Config) UserDB() (map[string][16]byte, error) {
	out := make(map[string][16]byte, len(c.Users))
	for _, u := range c.Users {
		var hash [16]byte
		switch {
		case u.Password != "":
			hash = ntHash(u.Password)
		default:
			raw, err := hex.DecodeString(u.NTHash)
			if err != nil || len(raw) != 16 {
				return nil, fmt.Errorf("user %q: bad nt_hash", u.Name)
			}
			copy(hash[:], raw)
		}
		out[strings.ToLower(u.Name)] = hash
	}
	return out, nil
}

// GuestAllowed reports whether unauthenticated guest sessions are permitted.
func (c *Config) GuestAllowed() bool {
	if c.AllowGuest != nil {
		return *c.AllowGuest
	}
	return len(c.Users) == 0
}

// ListenAddr parses `listen` into a TCP address.
func (c *Config) ListenAddr() (string, error) {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", c.Listen, err)
	}
	if net.ParseIP(host) == nil && host != "" {
		return "", fmt.Errorf("invalid listen address %q: bad host", c.Listen)
	}
	if port == "" {
		return "", fmt.Errorf("invalid listen address %q: missing port", c.Listen)
	}
	return net.JoinHostPort(host, port), nil
}

// Srv is the resolved runtime context shared by every worker.
type Srv struct {
	cfg        Config
	guid       [16]byte
	maxRead    uint32
	startFT    uint64
	users      map[string][16]byte
	allowGuest bool
	interfaces []Iface
	sessions   *Registry
	mailboxes  []*Mailbox
	leases     *LeaseTable
	// conns bounds the connections the server serves at once.
	conns *connLimiter
}

// Config exposes the parsed configuration.
func (s *Srv) Config() *Config { return &s.cfg }

// MaxRead is the advertised MaxReadSize, bounded by the achievable data path so
// a zero-copy READ always fits.
func (s *Srv) MaxRead() uint32 { return s.maxRead }

// GUID is the server GUID advertised in NEGOTIATE.
func (s *Srv) GUID() [16]byte { return s.guid }

// Interfaces lists the network interfaces reported for SMB3 multichannel.
func (s *Srv) Interfaces() []Iface { return s.interfaces }

// Sessions is the cross-connection session table (multichannel).
func (s *Srv) Sessions() *Registry { return s.sessions }

// Leases is the file-keyed lease registry, shared across all workers.
func (s *Srv) Leases() *LeaseTable { return s.leases }

// randBytes fills buf with cryptographically secure random bytes.
func randBytes(buf []byte) {
	if _, err := rand.Read(buf); err != nil {
		panic("samba: cannot read random bytes: " + err.Error())
	}
}
