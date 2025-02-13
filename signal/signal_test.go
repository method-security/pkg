// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package signal_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	sig "github.com/Method-Security/pkg/signal"
	"github.com/palantir/pkg/datetime"
)

func TestSignal(t *testing.T) {
	// Create a sample SignalReport instance
	now := datetime.DateTime(time.Now())
	report := sig.Signal{
		Content:      "Sample content",
		StartedAt:    now,
		CompletedAt:  nil,
		Status:       200,
		ErrorMessage: nil,
	}

	// Test the Content field
	if report.Content != "Sample content" {
		t.Errorf("Expected Content to be 'Sample content', but got '%s'", report.Content)
	}

	// Test the StartedAt field
	expectedStartedAt := now
	if report.StartedAt != expectedStartedAt {
		t.Errorf("Expected StartedAt to be '%s', but got '%s'", expectedStartedAt, report.StartedAt)
	}

	// Test the CompletedAt field
	if report.ErrorMessage != nil {
		t.Errorf("Expected ErrorMessage to be nil, but got '%s'", *report.ErrorMessage)
	}
}
func TestSignal_EncodeContent(t *testing.T) {
	// Create a sample Signal instance
	now := datetime.DateTime(time.Now())
	content := "Sample content"
	signal := sig.NewSignal(content, &now, nil, 200, nil)

	// Encode the content
	err := signal.EncodeContent()
	if err != nil {
		t.Errorf("Unexpected error while encoding content: %v", err)
	}

	marshalledContent := fmt.Sprintf("\"%v\"", content)
	// Verify the encoded content
	expectedEncoded := base64.StdEncoding.EncodeToString([]byte(marshalledContent))
	if signal.Content != expectedEncoded {
		t.Errorf("Expected encoded content to be '%s', but got '%s'", expectedEncoded, signal.Content)
	}
}

func TestSignal_AddError(t *testing.T) {
	// Create a sample Signal instance
	now := datetime.DateTime(time.Now())
	content := "Sample content"
	signal := sig.NewSignal(content, &now, nil, 200, nil)

	// Add an error to the Signal
	err := errors.New("Sample error")
	signal.AddError(err)

	// Verify the error message
	expectedErrorMessage := "Sample error"
	if *signal.ErrorMessage != expectedErrorMessage {
		t.Errorf("Expected ErrorMessage to be '%s', but got '%s'", expectedErrorMessage, *signal.ErrorMessage)
	}

	// Verify the status
	expectedStatus := 1
	if signal.Status != expectedStatus {
		t.Errorf("Expected Status to be %d, but got %d", expectedStatus, signal.Status)
	}

	// Add another error to the Signal
	err = errors.New("Another error")
	signal.AddError(err)

	// Verify the error message
	expectedErrorMessage += " Another error"
	if *signal.ErrorMessage != expectedErrorMessage {
		t.Errorf("Expected ErrorMessage to be '%s', but got '%s'", expectedErrorMessage, *signal.ErrorMessage)
	}

	// Verify the status
	if signal.Status != expectedStatus {
		t.Errorf("Expected Status to be %d, but got %d", expectedStatus, signal.Status)
	}
}
