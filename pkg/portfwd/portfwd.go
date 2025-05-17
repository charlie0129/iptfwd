package portfwd

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/coreos/go-iptables/iptables"
)

type Spec struct {
	Proto     Proto  `json:"proto"`
	IfaceFrom string `json:"iface"`
	PortFrom  uint16 `json:"sport"`
	PortTo    uint16 `json:"dport"`
	IPTo      string `json:"dip"` // currently v4 only
}

func NewFromComment(comment string) (*Spec, error) {
	components := strings.Split(comment, "_")
	if len(components) != 6 {
		return nil, errors.New("invalid comment")
	}
	if components[0] != "iptfwdspecv0" {
		return nil, errors.New("invalid comment")
	}

	var err error
	p := &Spec{}

	p.Proto, err = NewProto(components[1])
	if err != nil {
		return nil, err
	}

	p.IfaceFrom = components[2]

	portFrom, err := strconv.ParseUint(components[3], 10, 16)
	if err != nil {
		return nil, err
	}
	p.PortFrom = uint16(portFrom)

	ip := net.ParseIP(components[4])
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", components[4])
	}

	p.IPTo = ip.String()

	portTo, err := strconv.ParseUint(components[5], 10, 16)
	if err != nil {
		return nil, err
	}
	p.PortTo = uint16(portTo)

	return p, nil
}

func (p *Spec) Validate(ifaces []string) error {
	var err error

	_, err = NewProto(string(p.Proto))
	if err != nil {
		return err
	}

	ip := net.ParseIP(p.IPTo)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", p.IPTo)
	}

	if !slices.Contains(ifaces, p.IfaceFrom) {
		return fmt.Errorf("%s does not exist", p.IfaceFrom)
	}

	return nil
}

func (p *Spec) dstAddr() string {
	return p.IPTo + ":" + strconv.FormatUint(uint64(p.PortTo), 10)
}

func (p *Spec) Comment() string {
	return fmt.Sprintf("iptfwdspecv0_%s_%s_%d_%s_%d",
		p.Proto, p.IfaceFrom, p.PortFrom, p.IPTo, p.PortTo)
}

func (p *Spec) toPREROUTINGSpec() []string {
	return []string{
		"-p", string(p.Proto),
		"-i", p.IfaceFrom,
		"--dport", strconv.FormatUint(uint64(p.PortFrom), 10),
		"-j", "DNAT",
		"--to-destination", p.dstAddr(),
		"-m", "comment",
		"--comment", p.Comment(),
	}
}

func (p *Spec) toPOSTROUTINGSpec() []string {
	return []string{
		"-p", string(p.Proto),
		"-d", p.IPTo,
		// Only masquerade packets leaving the public iface, not every iface, so we can preserve sip.
		// However if the packet is meant to leave this host, do not add this.
		"-o", p.IfaceFrom,
		"--dport", strconv.FormatUint(uint64(p.PortFrom), 10),
		"-j", "MASQUERADE",
		"-m", "comment",
		"--comment", p.Comment(),
	}
}

func (p *Spec) toFORWARDSpec() []string {
	return []string{
		"-p", string(p.Proto),
		"-d", p.IPTo,
		"--dport", strconv.FormatUint(uint64(p.PortFrom), 10),
		"-m", "state",
		"--state", "NEW,ESTABLISHED,RELATED",
		"-j", "ACCEPT",
		"-m", "comment",
		"--comment", p.Comment(),
	}
}

// rules exist, expected rules, error
func (p *Spec) Exists(ipt *iptables.IPTables) (int, int, error) {
	rulesExist := 0

	spec := p.toPREROUTINGSpec()
	exists, err := ipt.Exists("nat", "PREROUTING", spec...)
	if err != nil {
		return rulesExist, 2, errors.Wrapf(err, "failed to check PREROUTING rule %s", spec)
	}
	if exists {
		rulesExist++
	}

	spec = p.toPOSTROUTINGSpec()
	exists, err = ipt.Exists("nat", "POSTROUTING", spec...)
	if err != nil {
		return rulesExist, 2, errors.Wrapf(err, "failed to check POSTROUTING rule %s", spec)
	}
	if exists {
		rulesExist++
	}

	// exists, err = ipt.Exists("nat", "FORWARD", p.toFORWARDSpec()...)
	// if err != nil {
	// 	return false, err
	// }
	// if !exists {
	// 	return false, nil
	// }

	return rulesExist, 2, nil
}

func (p *Spec) AppendUnique(ipt *iptables.IPTables) error {
	// Rewrite the destination IP of the packet (and back in the reply packet)
	spec := p.toPREROUTINGSpec()
	err := ipt.AppendUnique("nat", "PREROUTING", spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to append PREROUTING rule %s", spec)
	}

	// Rewrite the source IP of the packet to the IP of the gateway (and back in the reply packet)
	spec = p.toPOSTROUTINGSpec()
	err = ipt.AppendUnique("nat", "POSTROUTING", spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to append POSTROUTING rule %s", spec)
	}

	// If you don't have a default ACCEPT firewall rule, allow traffic to the destination
	// err = ipt.AppendUnique("nat", "FORWARD", p.toFORWARDSpec()...)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (p *Spec) DeleteIfExists(ipt *iptables.IPTables) error {
	spec := p.toPREROUTINGSpec()
	err := ipt.DeleteIfExists("nat", "PREROUTING", spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to delete PREROUTING rule %s", spec)
	}

	spec = p.toPOSTROUTINGSpec()
	err = ipt.DeleteIfExists("nat", "POSTROUTING", spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to delete POSTROUTING rule %s", spec)
	}

	// err = ipt.DeleteIfExists("nat", "FORWARD", p.toFORWARDSpec()...)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (p *Spec) String() string {
	return fmt.Sprintf("%s:%d ==> %s:%d/%s",
		p.IfaceFrom, p.PortFrom, p.IPTo, p.PortTo, p.Proto)
}

func (p *Spec) SlogAttr() []any {
	return []any{
		"iface", p.IfaceFrom,
		"sport", p.PortFrom,
		"dip", p.IPTo,
		"dport", p.PortTo,
		"proto", p.Proto,
	}
}

func (p *Spec) Equals(other *Spec) bool {
	return p.Proto == other.Proto &&
		p.IfaceFrom == other.IfaceFrom &&
		p.PortFrom == other.PortFrom &&
		p.PortTo == other.PortTo &&
		p.IPTo == other.IPTo
}
