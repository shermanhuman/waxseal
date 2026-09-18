package ops

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
)

// Check names.
const (
	CheckCert     = "cert"
	CheckExpiry   = "expiry"
	CheckMetadata = "metadata"
	CheckGSM      = "gsm"
	CheckCluster  = "cluster"
)

// Checks is the vocabulary of `check`.
var Checks = core.Enum{Name: "check", Choices: []core.Choice{
	{Value: CheckCert, Label: "Certificate", Help: "controller certificate present and not expiring"},
	{Value: CheckExpiry, Label: "Expiry", Help: "no key expired or expiring soon"},
	{Value: CheckMetadata, Label: "Metadata", Help: "config and metadata parse and are consistent"},
	{Value: CheckGSM, Label: "GSM", Help: "every referenced GSM version exists"},
	{Value: CheckCluster, Label: "Cluster", Help: "cluster secrets match metadata"},
}}

// Severities, in ascending order.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Finding is one result of a check. Info findings carry positive results so
// a run always has something to show.
type Finding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Subject  string `json:"subject,omitempty"` // secret, secret/key, or a path
	Message  string `json:"message"`
}

// CheckInput selects the checks to run.
type CheckInput struct {
	// Checks to run; empty means all. Explicitly named checks fail when
	// their port is unavailable; in an all-checks run they are skipped.
	Checks   []string
	WarnDays int
	// Progress, if set, is told what is being checked.
	Progress func(string)
}

// Check runs the selected checks and returns every finding.
func (s *Service) Check(ctx context.Context, in CheckInput) ([]Finding, error) {
	names := in.Checks
	all := len(names) == 0
	if all {
		names = Checks.Values()
	}
	if in.WarnDays <= 0 {
		in.WarnDays = 30
	}
	progress := in.Progress
	if progress == nil {
		progress = func(string) {}
	}

	var findings []Finding
	for _, name := range names {
		if err := Checks.Validate("check", name); err != nil {
			return nil, err
		}
		progress(name)
		switch name {
		case CheckCert:
			findings = append(findings, s.checkCert(in.WarnDays)...)
		case CheckExpiry:
			findings = append(findings, s.checkExpiry(in.WarnDays)...)
		case CheckMetadata:
			findings = append(findings, s.checkMetadata()...)
		case CheckGSM:
			if s.Store == nil {
				findings = append(findings, unavailable(all, CheckGSM, "no GSM credentials"))
				continue
			}
			findings = append(findings, s.checkGSM(ctx, progress)...)
		case CheckCluster:
			if s.Cluster == nil {
				findings = append(findings, unavailable(all, CheckCluster, "no cluster access"))
				continue
			}
			findings = append(findings, s.checkCluster(ctx, progress)...)
		}
	}
	return findings, nil
}

func unavailable(skippable bool, check, why string) Finding {
	if skippable {
		return Finding{Severity: SeverityInfo, Check: check, Message: "skipped: " + why}
	}
	return Finding{Severity: SeverityError, Check: check, Message: why}
}

// MaxSeverity returns the highest severity among findings ("" when none).
func MaxSeverity(findings []Finding) string {
	rank := map[string]int{SeverityInfo: 0, SeverityWarning: 1, SeverityError: 2}
	max := ""
	for _, f := range findings {
		if max == "" || rank[f.Severity] > rank[max] {
			max = f.Severity
		}
	}
	return max
}

func (s *Service) checkCert(warnDays int) []Finding {
	cfg, err := s.Repo.Config()
	if err != nil {
		return []Finding{{SeverityError, CheckCert, "", "cannot load config: " + err.Error()}}
	}
	pemData, err := s.Repo.Cert(cfg.Cert.RepoCertPath)
	if err != nil {
		return []Finding{{SeverityError, CheckCert, cfg.Cert.RepoCertPath, "cannot load certificate: " + err.Error()}}
	}
	cert, err := seal.ParseCert(pemData)
	if err != nil {
		return []Finding{{SeverityError, CheckCert, cfg.Cert.RepoCertPath, err.Error()}}
	}
	days := cert.DaysLeft(s.now())
	switch {
	case cert.NotAfter().Before(s.now()):
		return []Finding{{SeverityError, CheckCert, cfg.Cert.RepoCertPath,
			fmt.Sprintf("certificate expired %d days ago; rotate the controller key and run `waxseal reseal`", -days)}}
	case days < warnDays:
		return []Finding{{SeverityWarning, CheckCert, cfg.Cert.RepoCertPath,
			fmt.Sprintf("certificate expires in %d days; plan rotation, then `waxseal reseal`", days)}}
	}
	return []Finding{{SeverityInfo, CheckCert, cfg.Cert.RepoCertPath,
		fmt.Sprintf("certificate valid for %d days (fingerprint %s)", days, cert.Fingerprint()[:16])}}
}

func (s *Service) checkExpiry(warnDays int) []Finding {
	secrets, errs := s.Repo.AllMetadata()
	findings := loadFindings(CheckExpiry, errs)
	now := s.now()
	checked := 0
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}
		checked++
		for i := range m.Keys {
			k := &m.Keys[i]
			exp, ok := k.ExpiresAt()
			if !ok {
				continue
			}
			subject := m.ShortName + "/" + k.KeyName
			days := daysBetween(now, exp)
			switch {
			case exp.Before(now):
				findings = append(findings, Finding{SeverityError, CheckExpiry, subject, fmt.Sprintf("expired %d days ago", -days)})
			case days < warnDays:
				findings = append(findings, Finding{SeverityWarning, CheckExpiry, subject, fmt.Sprintf("expires in %d days", days)})
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{SeverityInfo, CheckExpiry, "", fmt.Sprintf("no expiring keys (%d secrets checked)", checked)})
	}
	return findings
}

func (s *Service) checkMetadata() []Finding {
	var findings []Finding
	if _, err := s.Repo.Config(); err != nil {
		findings = append(findings, Finding{SeverityError, CheckMetadata, "config", err.Error()})
	} else {
		findings = append(findings, Finding{SeverityInfo, CheckMetadata, "config", "valid"})
	}

	secrets, errs := s.Repo.AllMetadata()
	findings = append(findings, loadFindings(CheckMetadata, errs)...)
	checked := 0
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}
		checked++
		ss, err := s.Repo.Manifest(m)
		if err != nil {
			findings = append(findings, Finding{SeverityError, CheckMetadata, m.ShortName, err.Error()})
			continue
		}
		if got := ss.GetScope(); got != m.SealedSecret.Scope {
			findings = append(findings, Finding{SeverityError, CheckMetadata, m.ShortName,
				fmt.Sprintf("manifest scope is %s but metadata says %s; run `waxseal reseal %s`", got, m.SealedSecret.Scope, m.ShortName)})
		}
		sealed := ss.GetEncryptedKeys()
		for _, k := range m.Keys {
			if !slices.Contains(sealed, k.KeyName) {
				findings = append(findings, Finding{SeverityError, CheckMetadata, m.ShortName + "/" + k.KeyName,
					"in metadata but not in the manifest; run `waxseal reseal " + m.ShortName + "`"})
			}
		}
		for _, name := range sealed {
			if m.Key(name) == nil {
				findings = append(findings, Finding{SeverityWarning, CheckMetadata, m.ShortName + "/" + name,
					"in the manifest but not in metadata"})
			}
		}
	}
	findings = append(findings, Finding{SeverityInfo, CheckMetadata, "", fmt.Sprintf("%d secrets validated", checked)})
	return findings
}

func (s *Service) checkGSM(ctx context.Context, progress func(string)) []Finding {
	secrets, _ := s.Repo.AllMetadata()
	var findings []Finding
	checked := 0
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}
		for i := range m.Keys {
			k := &m.Keys[i]
			ref := k.ActiveRef()
			if ref == nil {
				continue
			}
			subject := m.ShortName + "/" + k.KeyName
			progress("gsm " + subject)
			checked++
			exists, err := s.Store.VersionExists(ctx, ref.SecretResource, ref.Version)
			switch {
			case err != nil:
				findings = append(findings, Finding{SeverityWarning, CheckGSM, subject, "cannot check: " + err.Error()})
			case !exists:
				findings = append(findings, Finding{SeverityError, CheckGSM, subject,
					fmt.Sprintf("%s version %s not found or disabled", ref.SecretResource, ref.Version)})
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{SeverityInfo, CheckGSM, "", fmt.Sprintf("all %d GSM versions present", checked)})
	}
	return findings
}

func (s *Service) checkCluster(ctx context.Context, progress func(string)) []Finding {
	secrets, _ := s.Repo.AllMetadata()
	var findings []Finding
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}
		progress("cluster " + m.ShortName)
		data, err := s.Cluster.GetSecret(ctx, m.SealedSecret.Namespace, m.SealedSecret.Name)
		if err != nil {
			findings = append(findings, Finding{SeverityWarning, CheckCluster, m.ShortName, "cannot read from cluster: " + err.Error()})
			continue
		}
		missing, extra := diffKeys(m, data)
		if len(missing) > 0 {
			findings = append(findings, Finding{SeverityError, CheckCluster, m.ShortName,
				"in metadata but not in the cluster: " + strings.Join(missing, ", ")})
		}
		if len(extra) > 0 {
			findings = append(findings, Finding{SeverityWarning, CheckCluster, m.ShortName,
				"in the cluster but not in metadata: " + strings.Join(extra, ", ")})
		}
		if len(missing) == 0 && len(extra) == 0 {
			findings = append(findings, Finding{SeverityInfo, CheckCluster, m.ShortName, fmt.Sprintf("cluster matches metadata (%d keys)", len(data))})
		}
	}
	return findings
}

// diffKeys compares metadata keys with a cluster secret's keys. Both
// results are sorted.
func diffKeys(m *core.SecretMetadata, cluster map[string][]byte) (missingInCluster, extraInCluster []string) {
	for _, k := range m.Keys {
		if _, ok := cluster[k.KeyName]; !ok {
			missingInCluster = append(missingInCluster, k.KeyName)
		}
	}
	for name := range cluster {
		if m.Key(name) == nil {
			extraInCluster = append(extraInCluster, name)
		}
	}
	slices.Sort(missingInCluster)
	slices.Sort(extraInCluster)
	return missingInCluster, extraInCluster
}

func loadFindings(check string, errs []error) []Finding {
	var findings []Finding
	for _, err := range errs {
		findings = append(findings, Finding{SeverityError, check, "", err.Error()})
	}
	return findings
}
