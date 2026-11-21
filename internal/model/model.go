// Package model defines the versioned, credential-free report contract.
package model

import "fmt"

const SchemaVersion = 1
const Marker = "<!-- kube-impact:report:v1 -->"

type ID struct {
	Group     string `json:"group"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (i ID) String() string { return fmt.Sprintf("%s/%s/%s/%s", i.Group, i.Kind, i.Namespace, i.Name) }

type Resource struct {
	ID     ID
	Object map[string]any
}
type Field struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
	Change string `json:"change,omitempty"`
}
type Change struct {
	Resource ID      `json:"resource"`
	Action   string  `json:"action"`
	Fields   []Field `json:"fields"`
}
type Finding struct {
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	Resource       ID     `json:"resource"`
	Field          string `json:"field"`
	Before         string `json:"before"`
	After          string `json:"after"`
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type Report struct {
	SchemaVersion int       `json:"schemaVersion"`
	Changes       []Change  `json:"changes"`
	Findings      []Finding `json:"findings"`
	Checks        []Check   `json:"checks"`
}

func Rank(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 0
}
