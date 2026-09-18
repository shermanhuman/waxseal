package proc

import (
	"context"
	"errors"
	"testing"
)

func TestRun(t *testing.T) {
	ctx := context.Background()

	out, err := Run(ctx, []byte("hello"), "cat")
	if err != nil || string(out) != "hello" {
		t.Errorf("cat: got %q, %v", out, err)
	}

	_, err = Run(ctx, nil, "sh", "-c", "echo oops >&2; exit 3")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 3 || exitErr.Stderr != "oops\n" {
		t.Errorf("non-zero exit: got %#v", err)
	}
	if exitErr != nil && exitErr.Error() != "sh: oops" {
		t.Errorf("Error() = %q", exitErr.Error())
	}

	_, err = Run(ctx, nil, "definitely-not-a-program-3f9a")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("missing program: got %v", err)
	}
}
