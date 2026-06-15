package rule_engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
)

// DstPort is a rule that matches connections by their destination port number.
// The match field stores the port as a string; the parsed integer is cached in Port.
type DstPort struct {
	RuleType constants.RuleType `json:"ruleType"`
	Port     int                `json:"port"`
	Policy   constants.Policy   `json:"policy"`
}

func (d DstPort) GetPolicy() constants.Policy {
	return d.Policy
}

func (d DstPort) Type() constants.RuleType {
	return constants.RuleDstPort
}

// Match expects value to be the destination port as a decimal string.
func (d DstPort) Match(value string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return port == d.Port
}

func (d DstPort) Value() string {
	return strconv.Itoa(d.Port)
}

func (d DstPort) Valid() bool {
	return d.Port >= 1 && d.Port <= 65535
}

// NewDstPortRule creates a DstPort rule after validating that portStr is a
// valid integer in the range 1–65535.  Returns an error otherwise.
func NewDstPortRule(portStr string, policy constants.Policy) (*DstPort, error) {
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		return nil, fmt.Errorf("DST-PORT match field is not a valid integer: %q", portStr)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("DST-PORT port %d is out of range 1–65535", port)
	}
	return &DstPort{
		RuleType: constants.RuleDstPort,
		Port:     port,
		Policy:   policy,
	}, nil
}
