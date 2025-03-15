package forward

import (
	"github.com/charlie0129/iptfwd/pkg/portfwd"
)

type Config struct {
	Rules []portfwd.Spec `json:"rules"`
}

func (c *Config) Contains(spec *portfwd.Spec) bool {
	for _, rule := range c.Rules {
		if rule.Equals(spec) {
			return true
		}
	}
	return false
}
