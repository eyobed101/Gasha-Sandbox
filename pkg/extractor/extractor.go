// extractor.go — family parser registry and dispatch.
//
// Every family parser registers itself via init() + Register(). The trigger
// layer calls Dispatch(family, data, source) which returns a parsed Config
// or nil. This mirrors CAPEv2's static_config_parsers() call chain.
package extractor

import "fmt"

// Config is the normalised output of a config extractor.
// Family parsers populate whatever fields they can; unused fields stay zero.
type Config struct {
	C2Servers []string               `json:"c2_servers,omitempty"`
	Protocol  string                 `json:"protocol,omitempty"`
	Port      int                    `json:"port,omitempty"`
	Mutex     string                 `json:"mutex,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

// Parser is the interface every family config extractor implements.
type Parser interface {
	Name() string
	Extract(data []byte) (*Config, error)
}

// registry maps normalised family names → parsers.
var registry = map[string]Parser{}

// Register adds a parser under one or more family name aliases.
func Register(name string, p Parser) {
	registry[name] = p
}

// Dispatch looks up a parser by normalised family name and runs Extract.
// Returns (nil, nil) when the family is unknown or the parser returns nil.
func Dispatch(family string, data []byte, source string) (*Config, error) {
	p, ok := registry[family]
	if !ok {
		return nil, nil
	}
	cfg, err := p.Extract(data)
	if err != nil {
		return nil, fmt.Errorf("extractor %s: %w", family, err)
	}
	if cfg == nil {
		return nil, nil
	}
	return cfg, nil
}
