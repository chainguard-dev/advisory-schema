/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package advisory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateCGAID(t *testing.T) {
	existingUIDs := make(map[string]struct{})
	numUUIDs := 10000

	// Compile the regular expression once
	regex := RegexCGA

	for i := 0; i < numUUIDs; i++ {
		uid, err := GenerateCGAID()
		require.NoError(t, err)

		// Test format
		require.True(t, regex.MatchString(uid))
		// Test uniqueness
		_, exists := existingUIDs[uid]
		require.False(t, exists, "Duplicate UUID generated: %s", uid)

		existingUIDs[uid] = struct{}{}
	}
}

func TestGenerateCGAIDWithSeed(t *testing.T) {
	// Compile the regular expression once
	regex := RegexCGA

	// Test deterministic output with a specific seed
	seed := int64(12345)
	expectedID := "CGA-556r-3q48-3w6v"

	generatedID, err := GenerateCGAIDWithSeed(seed)
	require.NoError(t, err, "Error generating CGA ID")

	require.Equal(t, expectedID, generatedID, "CGA ID does not match expected output for seed %d", seed)

	// Test format with a specific seed
	require.True(t, regex.MatchString(generatedID), "CGA ID does not match format: %s", generatedID)
}

func TestGenerateCGAIDFormat(t *testing.T) {
	// Compile the regular expression once
	regex := RegexCGA

	// Test multiple seeds for format compliance
	seeds := []int64{12345, 54321, 67890, 98765}
	for _, seed := range seeds {
		generatedID, err := GenerateCGAIDWithSeed(seed)
		require.NoError(t, err, "Error generating CGA ID for seed %d", seed)

		require.True(t, regex.MatchString(generatedID), "CGA ID does not match format for seed %d: %s", seed, generatedID)
	}
}

func TestValidateCGAID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "valid CGA",
			id:      "CGA-xg8w-q25p-9gcc",
			wantErr: false,
		},
		{
			name:    "invalid characters",
			id:      "CGA-4aj9-honk-9j91",
			wantErr: true,
		},
		{
			name:    "valid CVE (but not CGA)",
			id:      "CVE-2018-9999",
			wantErr: true,
		},
		{
			name:    "empty",
			id:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCGAID(tt.id); (err != nil) != tt.wantErr {
				t.Errorf("ValidateCGAID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
