package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestInteractive(t *testing.T) {
	// Buffers are never terminals, so the only way to be interactive in a
	// test is not at all; the rest of the rule is exercised by short-circuits.
	tty := func(any) bool { return true }
	if Interactive(false, env(nil), IsTerminal, nil, nil) {
		t.Error("non-terminal streams must not be interactive")
	}
	if !Interactive(false, env(nil), tty, nil, nil) {
		t.Error("terminals with no CI and no --no-input are interactive")
	}
	if Interactive(true, env(nil), tty, nil, nil) {
		t.Error("--no-input wins over a terminal")
	}
	for _, ci := range []string{"1", "true", "yes", "anything"} {
		if Interactive(false, env(map[string]string{"CI": ci}), tty, nil, nil) {
			t.Errorf("CI=%q must not be interactive", ci)
		}
	}
	if truthy("0") || truthy("false") || truthy("") {
		t.Error("0/false/empty must not count as CI")
	}
	if ColorEnabled(false, env(map[string]string{"NO_COLOR": "1"}), tty, nil) || ColorEnabled(true, env(nil), tty, nil) {
		t.Error("NO_COLOR and --no-color must disable colour")
	}
	if !ColorEnabled(false, env(nil), tty, nil) {
		t.Error("a terminal without NO_COLOR gets colour")
	}
}

func TestInputs_FlagWins(t *testing.T) {
	// A set flag is never prompted for, even when a prompter is available.
	script := &ScriptedPrompter{}
	in := NewInputs(true, false, script)

	got, err := in.String(Spec{Flag: "--namespace"}, true, "prod", "default", nil)
	if err != nil || got != "prod" {
		t.Errorf("String = %q, %v", got, err)
	}
	got, err = in.Choice(Spec{Flag: "--rotation"}, true, core.RotationStatic, core.RotationModes, "")
	if err != nil || got != core.RotationStatic {
		t.Errorf("Choice = %q, %v", got, err)
	}
	if len(script.Asked) != 0 {
		t.Errorf("prompted for %v although flags were set", script.Asked)
	}

	// A set flag is still validated.
	if _, err := in.Choice(Spec{Flag: "--rotation"}, true, "manual", core.RotationModes, ""); err == nil {
		t.Error("invalid flag value must be rejected")
	}
	_, err = in.String(Spec{Flag: "--bytes"}, true, "x", "", func(v string) error { return errors.New("not a number") })
	if err == nil || !strings.Contains(err.Error(), "--bytes") {
		t.Errorf("validation error must name the flag: %v", err)
	}
}

func TestInputs_NonInteractiveNamesTheFlag(t *testing.T) {
	in := NewInputs(false, false, &ScriptedPrompter{Answers: []string{"would be used if interactive"}})

	_, err := in.String(Spec{Flag: "--namespace"}, false, "", "", nil)
	var missing *core.MissingInputError
	if !errors.As(err, &missing) || missing.Field != "--namespace" {
		t.Errorf("String: got %v", err)
	}

	_, err = in.Choice(Spec{Flag: "--rotation"}, false, "", core.RotationModes, "")
	if !errors.As(err, &missing) || !strings.Contains(missing.Field, "--rotation (generated|external|static|unknown)") {
		t.Errorf("Choice: got %v", err)
	}

	_, err = in.Secret(Spec{Flag: "--from-file or --generate"})
	if !errors.As(err, &missing) || missing.Field != "--from-file or --generate" {
		t.Errorf("Secret: got %v", err)
	}

	var confirm *ConfirmRequiredError
	if err := in.Confirm("rotate 3 keys"); !errors.As(err, &confirm) || !strings.Contains(err.Error(), "pass --yes") {
		t.Errorf("Confirm: got %v", err)
	}
	if in.Offer("Add a key now") {
		t.Error("Offer must be false when not interactive")
	}
}

func TestInputs_PromptFallback(t *testing.T) {
	script := &ScriptedPrompter{Answers: []string{"prod", "external", "hunter2", "y", "n"}}
	in := NewInputs(true, false, script)

	if got, _ := in.String(Spec{Flag: "--namespace"}, false, "", "", nil); got != "prod" {
		t.Errorf("String = %q", got)
	}
	if got, _ := in.Choice(Spec{Flag: "--rotation"}, false, "", core.RotationModes, ""); got != "external" {
		t.Errorf("Choice = %q", got)
	}
	if got, _ := in.Secret(Spec{Flag: "--from-file"}); string(got) != "hunter2" {
		t.Errorf("Secret = %q", got)
	}
	if err := in.Confirm("rotate"); err != nil {
		t.Errorf("accepted confirm: %v", err)
	}
	if err := in.Confirm("rotate"); !errors.Is(err, ErrCancelled) {
		t.Errorf("declined confirm: got %v, want ErrCancelled", err)
	}
	if _, err := in.String(Spec{Flag: "--more"}, false, "", "", nil); err == nil {
		t.Error("running out of scripted answers must fail loudly")
	}

	bad := NewInputs(true, false, &ScriptedPrompter{Answers: []string{"manual"}})
	if _, err := bad.Choice(Spec{Flag: "--rotation"}, false, "", core.RotationModes, ""); err == nil {
		t.Error("a scripted answer outside the enum must fail")
	}
}

func TestInputs_YesOnlyAnswersConfirmations(t *testing.T) {
	in := NewInputs(false, true, nil)
	if err := in.Confirm("rotate"); err != nil {
		t.Errorf("--yes must accept confirmations: %v", err)
	}
	if _, err := in.Secret(Spec{Flag: "--from-file"}); err == nil {
		t.Error("--yes must never stand in for a value")
	}
	if in.Offer("Add a key now") {
		t.Error("--yes must not turn optional steps on")
	}
}

func TestArg(t *testing.T) {
	if v, ok := Arg([]string{"app"}, 0); !ok || v != "app" {
		t.Errorf("Arg 0 = %q, %v", v, ok)
	}
	if _, ok := Arg([]string{"app"}, 1); ok {
		t.Error("Arg past the end must not be set")
	}
}

func TestWithHint(t *testing.T) {
	if WithHint(nil, "x") != nil {
		t.Error("nil stays nil")
	}
	base := errors.New("config not found")
	err := WithHint(base, "run `waxseal init`")
	var h *HintError
	if !errors.As(err, &h) || h.Hint != "run `waxseal init`" || !errors.Is(err, base) {
		t.Errorf("got %#v", err)
	}
}
