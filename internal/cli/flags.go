package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// valueFlags supply a secret value without putting it in argv. Exactly one
// of --from-file and --generate may be given; on a terminal a masked prompt
// is the fallback.
type valueFlags struct {
	fromFile string
	generate bool
}

func (v *valueFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&v.fromFile, "from-file", "", "read the value from a file, or from stdin with -")
	cmd.Flags().BoolVar(&v.generate, "generate", false, "generate a random value")
	cmd.MarkFlagsMutuallyExclusive("from-file", "generate")
}

// resolve returns the value, or a generator when --generate was given. A
// single trailing newline is stripped from file and stdin content, so
// `echo pw | waxseal key set ... --from-file -` does what it looks like.
func (v *valueFlags) resolve(io *IO, stdin io.Reader, gen *core.GeneratorConfig, spec ui.Spec) ([]byte, *core.GeneratorConfig, error) {
	switch {
	case v.generate:
		if gen == nil {
			return nil, nil, &core.MissingInputError{Field: "--generator"}
		}
		return nil, gen, nil
	case v.fromFile == "-":
		data, err := readAll(stdin)
		return data, nil, err
	case v.fromFile != "":
		data, err := os.ReadFile(v.fromFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", v.fromFile, err)
		}
		return trimValue(data)
	}
	data, err := io.In.Secret(spec)
	return data, nil, err
}

func readAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	value, _, err := trimValue(data)
	return value, err
}

func trimValue(data []byte) ([]byte, *core.GeneratorConfig, error) {
	data = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	if len(data) == 0 {
		return nil, nil, core.NewValidationError("value", "must not be empty")
	}
	return data, nil, nil
}

// keyConfigFlags describe how a key is managed.
type keyConfigFlags struct {
	rotation  string
	generator string
	bytes     int
	template  string
	params    []string
	expires   string
}

func (k *keyConfigFlags) register(cmd *cobra.Command) {
	enumFlag(cmd, &k.rotation, "rotation", "how the key is rotated", core.RotationModes)
	enumFlag(cmd, &k.generator, "generator", "generator for generated keys", core.OfferedGeneratorKinds)
	cmd.Flags().IntVar(&k.bytes, "bytes", 32, "random bytes for the generator")
	cmd.Flags().StringVar(&k.template, "template", "", "make this a computed key rendered from the template; {{secret}} is the stored value")
	cmd.Flags().StringArrayVar(&k.params, "param", nil, "template value as name=value (repeatable)")
	cmd.Flags().StringVar(&k.expires, "expires", "", "expiry date (YYYY-MM-DD or RFC 3339), or 'none' to clear")
}

func (k *keyConfigFlags) paramMap() (map[string]string, error) {
	if len(k.params) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(k.params))
	for _, p := range k.params {
		name, value, ok := strings.Cut(p, "=")
		if !ok || name == "" {
			return nil, core.NewValidationError("--param", fmt.Sprintf("%q is not name=value", p))
		}
		m[name] = value
	}
	return m, nil
}

// parseExpiry accepts YYYY-MM-DD, RFC 3339, or "none" (returned as "").
func parseExpiry(s string) (string, error) {
	if s == "none" {
		return "", nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", core.NewValidationError("--expires", fmt.Sprintf("%q is not YYYY-MM-DD, RFC 3339 or 'none'", s))
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n <= 0 {
			return nil, errors.New("must be positive whole numbers separated by commas")
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one number is required")
	}
	return out, nil
}
