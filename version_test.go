package samba

import (
	"os"
	"regexp"
	"testing"
)

// Version (doc.go) is the single source of truth for the feature level the
// server implements, and the release workflow refuses to publish a tag that
// disagrees with it. These patterns let the test pull the two apart, so a
// release cannot ship a changelog and a binary that disagree with the tag.
var (
	semverRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	releasedRe = regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]`)
)

// TestVersionMatchesChangelog guards the release job: the newest *released*
// heading in CHANGELOG.md must name the version the code reports. Bumping one
// without the other is the easy mistake, and it is invisible until a tag is
// already published.
func TestVersionMatchesChangelog(t *testing.T) {
	if !semverRe.MatchString(Version) {
		t.Fatalf("Version %q is not MAJOR.MINOR.PATCH", Version)
	}
	body, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	// `[Unreleased]` carries no number, so the pattern skips it by shape rather
	// than by position.
	m := releasedRe.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatal("CHANGELOG.md has no released version heading")
	}
	if m[1] != Version {
		t.Fatalf("CHANGELOG.md documents %s but Version is %s", m[1], Version)
	}
}
