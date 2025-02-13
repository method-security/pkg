// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
)

type DemonstrationReport struct {
	Foo string   `json:"foo" yaml:"foo"`
	Bar int      `json:"bar" yaml:"bar"`
	Baz []string `json:"baz" yaml:"baz"`
}

func main() {
	report := DemonstrationReport{
		Foo: "foo",
		Bar: 42,
		Baz: []string{"baz1", "baz2"},
	}
	startedAt := datetime.DateTime(time.Now())
	status := 0
	signalConfig := writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL))
	jsonConfig := writer.NewOutputConfig(nil, writer.NewFormat(writer.JSON))
	yamlConfig := writer.NewOutputConfig(nil, writer.NewFormat(writer.YAML))

	_ = writer.Write(report, signalConfig, &startedAt, &startedAt, status, nil)
	fmt.Println()
	fmt.Println()
	_ = writer.Write(report, jsonConfig, &startedAt, &startedAt, status, nil)
	fmt.Println()
	fmt.Println()
	_ = writer.Write(report, yamlConfig, &startedAt, &startedAt, status, nil)

	os.Exit(0)
}
