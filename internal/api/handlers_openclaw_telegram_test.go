// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package api

import (
	"reflect"
	"testing"
)

func TestParseTelegramOwnerIDs(t *testing.T) {
	tests := []struct {
		name      string
		preferred string
		legacy    string
		wantIDs   []string
		wantJSON  string
		wantErr   bool
	}{
		{
			name:      "preferred list wins over legacy",
			preferred: "210408407,317748297",
			legacy:    "111",
			wantIDs:   []string{"210408407", "317748297"},
			wantJSON:  `["210408407","317748297"]`,
		},
		{
			name:      "preferred tolerates extra whitespace",
			preferred: "  210408407 , 317748297  ",
			wantIDs:   []string{"210408407", "317748297"},
			wantJSON:  `["210408407","317748297"]`,
		},
		{
			name:      "legacy single id used when preferred empty",
			preferred: "",
			legacy:    "210408407",
			wantIDs:   []string{"210408407"},
			wantJSON:  `["210408407"]`,
		},
		{
			name:      "duplicates deduplicated",
			preferred: "210408407,210408407,317748297",
			wantIDs:   []string{"210408407", "317748297"},
			wantJSON:  `["210408407","317748297"]`,
		},
		{
			name:      "both empty is an error",
			preferred: "",
			legacy:    "",
			wantErr:   true,
		},
		{
			name:      "non-numeric id rejected",
			preferred: "210408407,rm -rf /",
			wantErr:   true,
		},
		{
			name:    "legacy non-numeric rejected",
			legacy:  "hello",
			wantErr: true,
		},
		{
			name:      "overlong id rejected",
			preferred: "123456789012345678901", // 21 digits
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIDs, gotJSON, err := parseTelegramOwnerIDs(tt.preferred, tt.legacy)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTelegramOwnerIDs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
			if gotJSON != tt.wantJSON {
				t.Errorf("json: got %q, want %q", gotJSON, tt.wantJSON)
			}
		})
	}
}
