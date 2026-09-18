package reminder

import (
	"context"
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
)

func TestNew_Disabled(t *testing.T) {
	for name, cfg := range map[string]*config.RemindersConfig{
		"nil":      nil,
		"disabled": {Enabled: false, Provider: "tasks"},
		"none":     {Enabled: true, Provider: "none"},
	} {
		if _, err := New(context.Background(), cfg); !errors.Is(err, ErrDisabled) {
			t.Errorf("%s: got %v, want ErrDisabled", name, err)
		}
	}
	if _, err := New(context.Background(), &config.RemindersConfig{Enabled: true, Provider: "pager"}); err == nil {
		t.Error("unknown provider must be an error")
	}
}

func TestMulti(t *testing.T) {
	ctx := context.Background()
	ok, failing := NewFakeProvider(), NewFakeProvider()
	failing.SyncError = errors.New("calendar down")
	failing.DeleteError = errors.New("calendar down")
	m := Multi{ok, failing}

	secrets := []*core.SecretMetadata{{ShortName: "a"}, {ShortName: "b"}}
	res, err := m.SyncReminders(ctx, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || len(res.Errors) != 1 {
		t.Errorf("result = %+v, want 2 created and 1 error", res)
	}
	if len(ok.SyncCalls) != 1 || len(failing.SyncCalls) != 1 {
		t.Error("every provider must be called")
	}

	err = m.DeleteReminders(ctx, "a")
	if !errors.Is(err, failing.DeleteError) || len(ok.DeleteCalls) != 1 {
		t.Errorf("DeleteReminders: err=%v okCalls=%v", err, ok.DeleteCalls)
	}
}
