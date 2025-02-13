// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package writer_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
)

type TestReport struct {
	Foo string
	Bar int
	Baz []string
}

func TestWrite(t *testing.T) {

	startedAt := datetime.DateTime(time.Now())
	completedAt := datetime.DateTime(time.Now())

	// Test cases
	testCases := []struct {
		name         string
		report       any
		config       writer.OutputConfig
		startedAt    datetime.DateTime
		completedAt  *datetime.DateTime
		status       int
		errorMessage *string
		expectedErr  error
	}{
		{
			name:         "Signal Output",
			report:       TestReport{Foo: "foo", Bar: 42, Baz: []string{"baz1", "baz2"}},
			config:       writer.OutputConfig{Output: writer.NewFormat(writer.SIGNAL), FilePath: nil},
			startedAt:    startedAt,
			completedAt:  &completedAt,
			status:       0,
			errorMessage: nil,
			expectedErr:  nil,
		},
		{
			name:         "JSON Output",
			report:       TestReport{Foo: "foo", Bar: 42, Baz: []string{"baz1", "baz2"}},
			config:       writer.OutputConfig{Output: writer.NewFormat(writer.JSON), FilePath: nil},
			startedAt:    startedAt,
			completedAt:  &completedAt,
			status:       0,
			errorMessage: nil,
			expectedErr:  nil,
		},
		{
			name:         "YAML Output",
			report:       TestReport{Foo: "foo", Bar: 42, Baz: []string{"baz1", "baz2"}},
			config:       writer.OutputConfig{Output: writer.NewFormat(writer.YAML), FilePath: nil},
			startedAt:    startedAt,
			completedAt:  &completedAt,
			status:       0,
			errorMessage: nil,
			expectedErr:  nil,
		},
		{
			name:         "UNKNOWN Output",
			report:       TestReport{Foo: "foo", Bar: 42, Baz: []string{"baz1", "baz2"}},
			config:       writer.OutputConfig{Output: writer.NewFormat(writer.UNKNOWN), FilePath: nil},
			startedAt:    startedAt,
			completedAt:  &completedAt,
			status:       0,
			errorMessage: nil,
			expectedErr:  fmt.Errorf("unknown output format: %s", writer.UNKNOWN),
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := writer.Write(tc.report, tc.config, &tc.startedAt, tc.completedAt, tc.status, tc.errorMessage)
			if err != nil && err.Error() != tc.expectedErr.Error() {
				t.Errorf("Unexpected error while encoding content: %v", err)
			}
		})
	}
}
