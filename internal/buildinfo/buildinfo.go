// Package buildinfo exposes metadata injected into release binaries.
package buildinfo

import "fmt"

const Source = "https://github.com/jahwag/agentbus"

var (
	Version  = "dev"
	Revision = "unknown"
	Date     = "unknown"
)

func String() string {
	return fmt.Sprintf("agentbus %s (revision %s, built %s, %s)", Version, Revision, Date, Source)
}
