package ui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPrinter_StreamDiscipline(t *testing.T) {
	var out, errw bytes.Buffer
	p := NewPrinter(&out, &errw, false, false, false)

	p.Println("data")
	p.Table([]string{"NAME", "KEYS"}, [][]string{{"app", "3"}})
	p.KV([][2]string{{"Namespace", "prod"}, {"Scope", "strict"}})
	p.Success("done")
	p.Warn("careful")
	p.Error("failed")
	p.Info("note")
	p.Dim("quiet")
	p.Next([]string{"commit the files"})

	if strings.Contains(errw.String(), "data") || strings.Contains(errw.String(), "app") || strings.Contains(errw.String(), "prod") {
		t.Errorf("data leaked to stderr:\n%s", errw.String())
	}
	for _, chatter := range []string{"done", "careful", "failed", "note", "quiet", "Next:", "commit the files"} {
		if strings.Contains(out.String(), chatter) {
			t.Errorf("%q leaked to stdout:\n%s", chatter, out.String())
		}
		if !strings.Contains(errw.String(), chatter) {
			t.Errorf("%q missing from stderr:\n%s", chatter, errw.String())
		}
	}
	if strings.Contains(out.String(), "\033[") || strings.Contains(errw.String(), "\033[") {
		t.Error("colour must be off when disabled")
	}
}

func TestPrinter_Table(t *testing.T) {
	var out bytes.Buffer
	p := NewPrinter(&out, &bytes.Buffer{}, false, false, false)
	p.Table([]string{"NAME", "STATUS", "EXPIRY"}, [][]string{
		{"my-app-secrets", "active", ""},
		{"x", "retired", "expired"},
	})
	want := "NAME            STATUS   EXPIRY\n" +
		"my-app-secrets  active   -\n" +
		"x               retired  expired\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestPrinter_Color(t *testing.T) {
	var out, errw bytes.Buffer
	p := NewPrinter(&out, &errw, true, true, false)
	p.Success("ok")
	if !strings.HasPrefix(errw.String(), ansiGreen+"✓"+ansiReset+" ok") {
		t.Errorf("got %q", errw.String())
	}
	p.Table([]string{"H"}, nil)
	if !strings.Contains(out.String(), ansiBold) {
		t.Error("headers should be bold when colour is on")
	}
}

func TestPrinter_SpinWithoutTerminal(t *testing.T) {
	var out, errw bytes.Buffer
	p := NewPrinter(&out, &errw, false, false, false)
	err := p.Spin(context.Background(), "Checking GSM", func(progress func(string)) error {
		progress("app/password")
		return errors.New("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Errorf("fn's error must come back unchanged: %v", err)
	}
	if out.Len() != 0 {
		t.Error("spinner must not write to stdout")
	}
	if !strings.Contains(errw.String(), "Checking GSM...") || !strings.Contains(errw.String(), "app/password") {
		t.Errorf("plain progress lines expected on stderr:\n%s", errw.String())
	}
}
