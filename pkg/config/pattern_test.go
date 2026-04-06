package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHostnamePattern(t *testing.T) {
	assert.True(t, IsHostnamePattern("*.github.com"))
	assert.True(t, IsHostnamePattern("**.internal.cloudapp.net"))
	assert.True(t, IsHostnamePattern("foo.*.*.bar.com"))
	assert.True(t, IsHostnamePattern("*.*.internal.cloudapp.net"))
	assert.True(t, IsHostnamePattern("**.github.com"))
	assert.False(t, IsHostnamePattern("github.com"))
	assert.False(t, IsHostnamePattern("api.github.com"))
}

func TestCompileHostnamePattern(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"single wildcard", "*.github.com", false},
		{"double wildcard", "**.internal.cloudapp.net", false},
		{"middle wildcards", "actions.githubusercontent.com.*.*.internal.cloudapp.net", false},
		{"mixed", "foo.**.bar.*.baz.com", false},
		{"empty pattern", "", true},
		{"empty segment", "foo..bar.com", true},
		{"partial wildcard", "foo*.bar.com", true},
		{"partial wildcard mid", "foo.b*r.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := CompileHostnamePattern(tt.raw)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.raw, p.Raw)
			}
		})
	}
}

func TestHostnamePatternMatches(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		// Single wildcard (*)
		{
			"star matches one label",
			"*.github.com",
			"api.github.com",
			true,
		},
		{
			"star does not match zero labels",
			"*.github.com",
			"github.com",
			false,
		},
		{
			"star does not match two labels",
			"*.github.com",
			"a.b.github.com",
			false,
		},
		// Multiple wildcards
		{
			"two stars in middle",
			"actions.githubusercontent.com.*.*.internal.cloudapp.net",
			"actions.githubusercontent.com.j4d2msqy.phxx.internal.cloudapp.net",
			true,
		},
		{
			"two stars wrong count",
			"actions.githubusercontent.com.*.*.internal.cloudapp.net",
			"actions.githubusercontent.com.only1.internal.cloudapp.net",
			false,
		},
		{
			"two stars too many",
			"actions.githubusercontent.com.*.*.internal.cloudapp.net",
			"actions.githubusercontent.com.a.b.c.internal.cloudapp.net",
			false,
		},
		// Double wildcard (**)
		{
			"doublestar matches one label",
			"**.internal.cloudapp.net",
			"phxx.internal.cloudapp.net",
			true,
		},
		{
			"doublestar matches multiple labels",
			"**.internal.cloudapp.net",
			"a.b.c.internal.cloudapp.net",
			true,
		},
		{
			"doublestar does not match zero labels",
			"**.internal.cloudapp.net",
			"internal.cloudapp.net",
			false,
		},
		{
			"doublestar with prefix",
			"actions.githubusercontent.com.**.internal.cloudapp.net",
			"actions.githubusercontent.com.abc.def.ghi.internal.cloudapp.net",
			true,
		},
		{
			"doublestar with prefix one label",
			"actions.githubusercontent.com.**.internal.cloudapp.net",
			"actions.githubusercontent.com.abc.internal.cloudapp.net",
			true,
		},
		// Literal only (no wildcards — still valid pattern)
		{
			"exact match no wildcards",
			"github.com",
			"github.com",
			true,
		},
		{
			"no match no wildcards",
			"github.com",
			"api.github.com",
			false,
		},
		// Mixed patterns
		{
			"star then doublestar",
			"*.**.example.com",
			"a.b.c.example.com",
			true,
		},
		{
			"star then doublestar minimum",
			"*.**.example.com",
			"a.b.example.com",
			true,
		},
		{
			"star then doublestar too few",
			"*.**.example.com",
			"a.example.com",
			false,
		},
		// Region-style patterns
		{
			"region wildcard",
			"storage.*.azure.com",
			"storage.westus2.azure.com",
			true,
		},
		{
			"region wildcard no match",
			"storage.*.azure.com",
			"storage.azure.com",
			false,
		},
		// Trailing mismatch
		{
			"wrong suffix",
			"*.github.com",
			"api.gitlab.com",
			false,
		},
		{
			"wrong prefix",
			"actions.*.internal.cloudapp.net",
			"other.foo.internal.cloudapp.net",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := CompileHostnamePattern(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, tt.want, p.Matches(tt.hostname))
		})
	}
}
