package portfwd

import "errors"

type Proto string

const ProtoTCP Proto = "tcp"
const ProtoUDP Proto = "udp"

func NewProto(p string) (Proto, error) {
	switch p {
	case string(ProtoTCP):
		return ProtoTCP, nil
	case string(ProtoUDP):
		return ProtoUDP, nil
	default:
		return Proto(""), errors.New("invalid proto")
	}
}
