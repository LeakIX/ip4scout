package ip4scout

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

// CREDIT MENTION : to https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/runner/ports.go#L173
func ParsePortsList(data string) (portList []layers.TCPPort, err error) {
	ports := make(map[int]struct{})
	ranges := strings.Split(data, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports[i] = struct{}{}
			}
		} else {
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			}
			ports[port] = struct{}{}
		}
	}
	for port := range ports {
		portList = append(portList, layers.TCPPort(port))
	}
	return portList, nil
}
