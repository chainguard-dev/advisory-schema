/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package v1

import (
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

type Document struct {
	Package Package `yaml:"package"`

	Advisories Advisories `yaml:"advisories,omitempty"`
}

func (d Document) Name() string {
	return d.Package.Name
}

type Package struct {
	Name string `yaml:"name"`
}

type Advisories map[string][]Entry

type Entry struct {
	Timestamp       time.Time         `yaml:"timestamp"`
	Status          vex.Status        `yaml:"status"`
	Justification   vex.Justification `yaml:"justification,omitempty"`
	ImpactStatement string            `yaml:"impact,omitempty"`
	ActionStatement string            `yaml:"action,omitempty"`
	FixedVersion    string            `yaml:"fixed-version,omitempty"`
}
