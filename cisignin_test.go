package githubaction_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"gitlab.corp.cloudlinux.com/els-automation/securechain-cli/internal/client/portal/portaltest"
	"gitlab.tuxcare.com/i/securechain-coverage/wire"
)

// The CI sign-in of the action (task SC-1473; doc 19 §1, "The CI sign-in",
// task SC-1444): with no portal-token and a portal-url, the CLI trades the
// OIDC token of the job for a portal token, so the repository keeps no
// portal token in a secret.

// ciPortalToken is the portal token of the exchange: a well-formed token,
// which the CLI checks before it uses it.
const ciPortalToken = "tuxr_acct_company_0123456789abcdef0123456789abcdef0123456789abcdef"

// requestToken is ACTIONS_ID_TOKEN_REQUEST_TOKEN of the fake runner.
const requestToken = "gh-request-t0ken"

// ciFar is a fixed end of the tokens, far after any run: the tests read no
// wall clock, and a run signs in once.
var ciFar = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

// oidcJWT is an unsigned OIDC token for aud: only the portal checks the
// signature, and the CLI reads the aud claim.
func oidcJWT(aud string) string {
	b, _ := json.Marshal(map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": aud,
		"repository": "acme/shop", "ref": "refs/heads/main", "exp": ciFar.Unix()})
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{}`)) + "." + enc.EncodeToString(b) + ".sig"
}

// githubTokenService is the token service of the runner: it answers a GET
// of /idtoken with the request token and the audience, and fails each other
// call, with the call in the test's errors.
func githubTokenService(t *testing.T, audience string) (srv *httptest.Server, calls func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/idtoken" || r.Header.Get("Authorization") != "Bearer "+requestToken ||
			r.URL.Query().Get("audience") != audience {
			t.Errorf("the token service got an unexpected call: %s %s (audience %q)", r.Method, r.URL.Path,
				r.URL.Query().Get("audience"))
			http.Error(w, "unexpected call", http.StatusTeapot)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 1, "value": oidcJWT(audience)})
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// ciPortal is the fake portal with the registry credential and the CI
// sign-in route; sent records each OIDC token that came to the route.
func ciPortal(t *testing.T) (srv *portaltest.Server, sent func() []string) {
	t.Helper()
	var mu sync.Mutex
	var tokens []string
	srv = portaltest.New(t, portaltest.Options{
		Tenant:   wire.Tenant{Subdomain: "acme", AccountRef: "ACME-1"},
		Registry: "https://registry.example.test",
		RegistryCredential: &wire.RegistryCredential{
			Contract: wire.Contract, Registry: "https://registry.example.test",
			Username: "acme", Token: registrySecret, Source: "staff",
		},
		CIToken: func(in wire.CITokenRequest) portaltest.CIAnswer {
			mu.Lock()
			tokens = append(tokens, in.Token)
			mu.Unlock()
			return portaltest.CIAnswer{Status: 200, Body: wire.CITokenResponse{AccessToken: ciPortalToken,
				TokenType: "Bearer", ExpiresAt: ciFar}}
		},
	})
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), tokens...) }
}

// A job with id-token: write and no portal-token: the credential step signs
// in with the OIDC token of the job, for the audience of portal-url, and
// fetches the registry credential with the portal token of the exchange.
// No token of the sign-in reaches the log.
func TestWithNoPortalTokenTheCredentialStepSignsInWithTheOIDCTokenOfTheJob(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv, sent := ciPortal(t)
	gh, calls := githubTokenService(t, srv.URL)
	j := newJob(t, srv, "job-dir", "registry")
	delete(j.vars, "PORTAL_TOKEN")
	// A slash at the end of portal-url: the audience has none (doc 19 §1).
	j.vars["PORTAL_URL"] = srv.URL + "/"
	j.vars["ACTIONS_ID_TOKEN_REQUEST_URL"] = gh.URL + "/idtoken?api-version=2.0"
	j.vars["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = requestToken

	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err != nil {
		t.Fatalf("the credential step failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got := j.exported(t)["TUXCARE_TOKEN"]; got != registrySecret {
		t.Errorf("$GITHUB_ENV TUXCARE_TOKEN = %q, want the registry credential", got)
	}
	if calls() == 0 {
		t.Error("the step asked the token service of the runner for no OIDC token")
	}
	oidc := oidcJWT(srv.URL)
	if got := sent(); len(got) == 0 || got[0] != oidc {
		t.Errorf("the portal's CI sign-in got %d token(s), want the OIDC token of the job", len(got))
	}
	for _, r := range srv.Requests() {
		if r.Path == "/securechain/v1/ci-token" {
			continue
		}
		if r.Authorization != "Bearer "+ciPortalToken {
			t.Errorf("%s carried %q, want the portal token of the exchange", r.Path, r.Authorization)
		}
	}
	for _, secret := range []string{oidc, requestToken, ciPortalToken} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the step's log holds a token of the CI sign-in:\n%s%s", stdout, stderr)
		}
	}
}

// What the CLI gets from the portal inputs in the run step. An input that is
// empty leaves the job's own variable as it was, and the input's own
// variable never reaches the CLI: the CLI removes SECURECHAIN_PORTAL_TOKEN
// from the programs that it starts, and no other name (doc 10).
func TestTheRunStepGivesTheCLIThePortalInputs(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	const jobToken, jobURL = "sctest_jobtoken", "https://job.example.test"
	for _, tc := range []struct {
		name string
		vars map[string]string
		want string
	}{
		{"portal-token and portal-url", map[string]string{"PORTAL_TOKEN": "sctest_faketoken", "PORTAL_URL": "https://acme.example.com"},
			"token=sctest_faketoken url=https://acme.example.com input=unset"},
		{"portal-url alone: the CI sign-in", map[string]string{"PORTAL_URL": "https://acme.example.com"},
			"token=unset url=https://acme.example.com input=unset"},
		{"empty inputs, as the runner passes an input not given", map[string]string{"PORTAL_TOKEN": "", "PORTAL_URL": ""},
			"token=unset url=unset input=unset"},
		{"empty inputs keep the job's own variables", map[string]string{"PORTAL_TOKEN": "", "PORTAL_URL": "",
			"SECURECHAIN_PORTAL_TOKEN": jobToken, "SECURECHAIN_PORTAL_URL": jobURL},
			"token=" + jobToken + " url=" + jobURL + " input=unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newJob(t, fakePortal(t), "none", "check")
			delete(j.vars, "PORTAL_TOKEN")
			delete(j.vars, "PORTAL_URL")
			for k, v := range tc.vars {
				j.vars[k] = v
			}
			j.vars["SARIF"] = "false"
			dir := t.TempDir()
			wrapDir := t.TempDir()
			wrapper := "#!/bin/sh\necho \"token=${SECURECHAIN_PORTAL_TOKEN-unset} url=${SECURECHAIN_PORTAL_URL-unset} input=${PORTAL_TOKEN-unset}\" > \"$LOG\"\n"
			if err := os.WriteFile(filepath.Join(wrapDir, "securechain"), []byte(wrapper), 0o755); err != nil {
				t.Fatal(err)
			}
			j.vars["PATH"] = wrapDir + string(os.PathListSeparator) + os.Getenv("PATH")
			j.vars["LOG"] = filepath.Join(dir, "env")
			stdout, stderr, err := j.run(t, bin, runStepScript(t), npmProject(t))
			if err != nil {
				t.Fatalf("the run step failed: %v\n%s%s", err, stdout, stderr)
			}
			b, err := os.ReadFile(j.vars["LOG"])
			if err != nil {
				t.Fatalf("the run step ran no securechain: %v", err)
			}
			if got := strings.TrimSpace(string(b)); got != tc.want {
				t.Errorf("securechain got %q, want %q", got, tc.want)
			}
		})
	}
}

// portal-token is optional, and portal-url is an input: a workflow that
// names neither still loads, and one with the CI sign-in names portal-url.
func TestPortalTokenIsOptionalAndPortalURLIsAnInput(t *testing.T) {
	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Inputs map[string]struct {
			Required bool    `yaml:"required"`
			Default  *string `yaml:"default"`
		} `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"portal-token", "portal-url"} {
		in, ok := a.Inputs[name]
		if !ok {
			t.Errorf("action.yml has no input %s", name)
			continue
		}
		if in.Required || in.Default == nil || *in.Default != "" {
			t.Errorf("input %s: required %v, default %v; want optional with an empty default", name, in.Required, in.Default)
		}
	}
}

// The README and doc 17 show the job of the CI sign-in: the permission
// id-token: write and portal-url, with no portal-token. Review of SC-1473
// (round 1, Codex): GitHub gives ACTIONS_ID_TOKEN_REQUEST_TOKEN and
// ACTIONS_ID_TOKEN_REQUEST_URL to each step of such a job, the customer's
// own npm ci too, and with them an install script gets an OIDC token for
// the portal and trades it for a portal token. Each example removes them in
// its install step.
func TestTheExamplesOfTheCISignInRemoveTheTokenServiceFromTheInstall(t *testing.T) {
	const unset = "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL"
	for _, path := range []string{"README.md", "../../../docs/17-getting-started.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc := string(b)
		if !strings.Contains(doc, "portal-url:") {
			t.Errorf("%s does not show portal-url", path)
		}
		// The text after the first id-token: write is the example of the
		// CI sign-in (and the prose after it). Each npm ci there comes
		// right after the line that removes the two variables.
		_, example, ok := strings.Cut(doc, "id-token: write")
		if !ok {
			t.Errorf("%s does not show id-token: write", path)
			continue
		}
		installs := 0
		prev := ""
		for _, line := range strings.Split(example, "\n") {
			l := strings.TrimSpace(line)
			if l == "npm ci" || strings.HasSuffix(l, "run: npm ci") {
				installs++
				if prev != unset {
					t.Errorf("%s: the install step %q of the CI sign-in keeps the token service of the runner", path, l)
				}
			}
			prev = l
		}
		if installs == 0 {
			t.Errorf("%s: the example of the CI sign-in has no install step", path)
		}
	}
}
