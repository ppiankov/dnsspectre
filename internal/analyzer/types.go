package analyzer

// Severity indicates the urgency of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingType identifies the class of DNS hygiene issue.
type FindingType string

const (
	DanglingCNAME         FindingType = "DANGLING_CNAME"
	SubdomainTakeoverRisk FindingType = "SUBDOMAIN_TAKEOVER_RISK"
	NoCAARecord           FindingType = "NO_CAA_RECORD"
	DanglingMX            FindingType = "DANGLING_MX"
	DanglingNS            FindingType = "DANGLING_NS"
)

// Record is a provider-agnostic DNS record.
type Record struct {
	Name   string
	Type   string
	Values []string
	TTL    int64
}

// Finding represents a single DNS hygiene issue detected by the analyzer.
type Finding struct {
	Type     FindingType
	Severity Severity
	Domain   string // the record name that has the issue
	Record   Record // the source record
	Target   string // the resolved/checked target
	Service  string // matched service name (only for SUBDOMAIN_TAKEOVER_RISK)
	Detail   string // human-readable explanation
}
