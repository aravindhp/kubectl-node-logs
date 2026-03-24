/*
Copyright © 2023 Aravindh Puthiyaparambil <aravindhp@gmail.com>
*/

package nodelogs

import (
	"bytes"
	"strings"
	"testing"
)

// TestOutputDirectoryEntriesOrContent_OldHrefFormat tests the HTML parser
// against the old kubelet directory listing format that uses href attributes.
func TestOutputDirectoryEntriesOrContent_OldHrefFormat(t *testing.T) {
	input := `<pre><a href="amazon/">amazon/</a>
<a href="audit/">audit/</a>
<a href="boot.log">boot.log</a>
<a href="messages">messages</a>
</pre>
`
	var out bytes.Buffer
	if err := outputDirectoryEntriesOrContent(&out, strings.NewReader(input), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	for _, want := range []string{"amazon/", "audit/", "boot.log", "messages"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<a") || strings.Contains(got, "<pre>") {
		t.Errorf("output should not contain raw HTML, got:\n%s", got)
	}
}

// TestOutputDirectoryEntriesOrContent_NewNoHrefFormat tests the HTML parser
// against the new kubelet directory listing format that omits href attributes.
// This is the format used in Kubernetes 1.28 and later.
func TestOutputDirectoryEntriesOrContent_NewNoHrefFormat(t *testing.T) {
	input := `<pre>
<a>amazon/</a>
<a>audit/</a>
<a>boot.log</a>
<a>messages</a>
</pre>
`
	var out bytes.Buffer
	if err := outputDirectoryEntriesOrContent(&out, strings.NewReader(input), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	for _, want := range []string{"amazon/", "audit/", "boot.log", "messages"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<a") || strings.Contains(got, "<pre>") {
		t.Errorf("output should not contain raw HTML, got:\n%s", got)
	}
}

// TestOutputDirectoryEntriesOrContent_WithPrefix verifies that the node name
// prefix is correctly prepended to each directory entry.
func TestOutputDirectoryEntriesOrContent_WithPrefix(t *testing.T) {
	input := `<pre><a>messages</a>
<a>cron</a>
</pre>
`
	prefix := []byte("node-1 ")
	var out bytes.Buffer
	if err := outputDirectoryEntriesOrContent(&out, strings.NewReader(input), prefix); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	for _, want := range []string{"node-1 messages", "node-1 cron"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
}

// TestOutputDirectoryEntriesOrContent_PlainText verifies that plain-text
// content (e.g., journal logs) passes through unchanged.
func TestOutputDirectoryEntriesOrContent_PlainText(t *testing.T) {
	logLine := "Mar 24 10:00:00 node kubelet[1234]: some log line\n"
	var out bytes.Buffer
	if err := outputDirectoryEntriesOrContent(&out, strings.NewReader(logLine), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := out.String(); got != logLine {
		t.Errorf("expected plain text to pass through unchanged\nwant: %q\ngot:  %q", logLine, got)
	}
}

// TestWriteTo_RawHTMLDirectoryListing verifies that even when raw=true (set
// when --query is used), an HTML directory listing response is parsed rather
// than emitted as raw HTML.  This is the root cause of the reported bug.
func TestWriteTo_RawHTMLDirectoryListing(t *testing.T) {
	htmlListing := `<pre>
<a>amazon/</a>
<a>audit/</a>
<a>messages</a>
</pre>
`
	var out bytes.Buffer
	req := &logRequest{
		node:       "my-node",
		raw:        true,
		skipPrefix: true,
	}
	if err := req.writeToReader(&out, strings.NewReader(htmlListing)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	for _, want := range []string{"amazon/", "audit/", "messages"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<a") || strings.Contains(got, "<pre>") {
		t.Errorf("raw HTML should not appear in output when content is a directory listing, got:\n%s", got)
	}
}
