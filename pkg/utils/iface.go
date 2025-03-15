package utils

import (
	"net"
)

func ListIfaces() ([]string, error) {
	ifaceList, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifaces []string
	for _, iface := range ifaceList {
		ifaces = append(ifaces, iface.Name)
	}

	return ifaces, nil
}
