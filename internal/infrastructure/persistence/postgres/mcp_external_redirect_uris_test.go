package repo

import (
	"reflect"
	"testing"
)

func TestDecodeMCPExternalRedirectURIs(t *testing.T) {
	got, ok := decodeMCPExternalRedirectURIs(`[
		"https://client.example.test/oauth/callback",
		"http://127.0.0.1:43127/callback"
	]`)
	want := []string{
		"https://client.example.test/oauth/callback",
		"http://127.0.0.1:43127/callback",
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeMCPExternalRedirectURIs() = (%v, %v), want (%v, true)", got, ok, want)
	}
}

func TestDecodeMCPExternalRedirectURIsRejectsUnsafeOrMalformedValues(t *testing.T) {
	for _, value := range []string{
		`null`,
		`[]`,
		`["https://client.example.test/callback","https://client.example.test/callback"]`,
		`["http://client.example.test/callback"]`,
		`["https://user@client.example.test/callback"]`,
		`["https://client.example.test/callback#fragment"]`,
		`["https://client.example.test/callback?state=existing"]`,
		`[" https://client.example.test/callback"]`,
		`["not a URL"]`,
		`[null]`,
	} {
		t.Run(value, func(t *testing.T) {
			if got, ok := decodeMCPExternalRedirectURIs(value); ok || got != nil {
				t.Fatalf("decodeMCPExternalRedirectURIs(%q) = (%v, %v), want (nil, false)", value, got, ok)
			}
		})
	}
}
