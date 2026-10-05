// Package githubaction_test drives the GitHub composite action's own
// registry-credential script against a real securechain binary built from
// this checkout, and a fake portal, so a change to action.yml that breaks
// the credential the customer's later npm ci/pip install steps read is
// caught here rather than on a customer's first CI run.
//
// The script is extracted from action.yml by parsing the YAML, not copied by
// hand into this file, so the test fails the moment the file's real text
// changes underneath it.
package githubaction_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"gitlab.corp.cloudlinux.com/els-automation/securechain-cli/internal/client/auth"
	"gitlab.corp.cloudlinux.com/els-automation/securechain-cli/internal/client/portal/portaltest"
	"gitlab.corp.cloudlinux.com/els-automation/securechain-cli/internal/registrycred"
	"gitlab.tuxcare.com/i/securechain-coverage/wire"
)

// registrySecret has a single quote in it: `registry env --format shell`
// (the GitLab template's own equivalent step) has to escape it, and a test
// with a plain token cannot tell. Mirrors internal/cli/registry_test.go.
const registrySecret = "reg-t0ken-it's-s3cret"

// securechainBin is the CLI built from this checkout by TestMain, or "" when
// there is no bash to run the extracted script with.
var securechainBin string

// fakeNpmDir holds the npm every script in this package finds first on PATH
// (writeFakeNpm).
var fakeNpmDir string

// TestMain builds the CLI once. The work is in buildAndRun so that its
// deferred RemoveAll runs: os.Exit skips deferred calls, and each run
// left a 39 MB binary in the temporary directory.
func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

func buildAndRun(m *testing.M) int {
	if _, err := exec.LookPath("bash"); err != nil {
		return m.Run() // every test skips itself; see securechainBinaryOrSkip
	}
	dir, err := os.MkdirTemp("", "securechain-action-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "go env GOMOD:", err)
		return 1
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		fmt.Fprintln(os.Stderr, "this package is not inside a Go module")
		return 1
	}
	root := filepath.Dir(gomod)

	bin := filepath.Join(dir, "securechain")
	build := exec.Command("go", "build", "-o", bin, "./cmd/securechain")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build ./cmd/securechain: %v\n%s", err, out)
		return 1
	}
	fakeNpmDir = filepath.Join(dir, "npm")
	if err := writeFakeNpm(fakeNpmDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	securechainBin = bin
	return m.Run()
}

// fakeTools answer `--version` and nothing else. `registry login` in an
// npm project detects npm, and the detection runs `npm --version`. Found in
// CI on 28 September 2026 (pipeline 36805): golang:1.26.6 has no npm, and
// each test that ran `registry login` in an npm project failed with "tool is
// not installed: npm". On a developer machine the same tests ran the npm of
// the machine. Found again the same day (pipeline 36838): the bun and yarn
// berry steps detect bun and yarn the same way, and the runner has neither.
// hermeticEnv puts these tools on PATH before the machine's own, so each
// machine runs the same ones. The versions are the ones doc 07 measured;
// yarn is the yarn classic these tests were written beside, which also
// decides always-auth (ruling D-R11).
var fakeTools = map[string]string{"npm": "11.19.0", "bun": "1.3.14", "yarn": "1.22.22"}

const fakeToolScript = `#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
	echo %s
	exit 0
fi
echo "the fake %s of this test answers only --version, not: $*" >&2
exit 97
`

// writeFakeNpm writes each of fakeTools into dir.
func writeFakeNpm(dir string) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	for name, version := range fakeTools {
		script := fmt.Sprintf(fakeToolScript, version, name)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func securechainBinaryOrSkip(t *testing.T) string {
	t.Helper()
	if securechainBin == "" {
		t.Skip("no bash on this machine to run the action's script with")
	}
	return securechainBin
}

// actionYAML is the shape of action.yml this test needs: enough to find a
// step by its name or its id and read its script and its condition back.
type actionYAML struct {
	Runs struct {
		Steps []struct {
			ID   string `yaml:"id"`
			Name string `yaml:"name"`
			If   string `yaml:"if"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func actionSteps(t *testing.T) actionYAML {
	t.Helper()
	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var a actionYAML
	if err := yaml.Unmarshal(data, &a); err != nil {
		t.Fatalf("action.yml did not parse: %v", err)
	}
	return a
}

// namedStep returns the run: block and the if: of the one step whose name is
// name.
func namedStep(t *testing.T, name string) (run, cond string) {
	t.Helper()
	for _, s := range actionSteps(t).Runs.Steps {
		if s.Name == name {
			if s.Run == "" {
				t.Fatalf("action.yml's %q step has no run: block", name)
			}
			return s.Run, s.If
		}
	}
	t.Fatalf("action.yml has no step named %q", name)
	return "", ""
}

// registryCredentialScript extracts the "Configure the registry credential"
// step's run: block from action.yml.
func registryCredentialScript(t *testing.T) string {
	t.Helper()
	run, _ := namedStep(t, "Configure the registry credential")
	return run
}

// cleanupScript extracts the last step's run: block, which removes the job
// directory and puts bun's .npmrc back.
func cleanupScript(t *testing.T) string {
	t.Helper()
	run, _ := namedStep(t, "Remove the job directory")
	return run
}

// runStepScript extracts the run: block of the step whose id is "run", the
// one that runs the command. Its inputs reach it through the step's env:
// the tests set j.vars.
func runStepScript(t *testing.T) string {
	t.Helper()
	for _, s := range actionSteps(t).Runs.Steps {
		if s.ID != "run" {
			continue
		}
		return s.Run
	}
	t.Fatal(`action.yml has no step with id "run"`)
	return ""
}

// writeNpmProjectFiles drops a package.json and a package-lock.json into dir:
// a directory a real npm detection claims with confidence (doc 03, "Where
// the ecosystem comes from").
func writeNpmProjectFiles(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// npmProject is a fresh temporary directory an npm detection claims.
func npmProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeNpmProjectFiles(t, dir)
	return dir
}

// cleanBunLock names only the fake portal's registry; foreignBunLock names
// another host. Both are the shape bun 1.3.14 writes (doc 07).
const (
	cleanBunLock = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"left-pad\": [\"left-pad@1.3.0\", " +
		"\"https://registry.example.test/npm/left-pad/-/left-pad-1.3.0.tgz\", {}, \"sha512-XI5M\"],\n  }\n}\n"
	foreignBunLock = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"left-pad\": [\"left-pad@1.3.0\", " +
		"\"https://evil.example/left-pad-1.3.0.tgz\", {}, \"sha512-XI5M\"],\n  }\n}\n"
)

// projectWith is a fresh temporary directory with a package.json and the
// file name, empty or with content.
func projectWith(t *testing.T, name, content string) string {
	t.Helper()
	dir := npmProject(t)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakePortal starts a fake portal whose registry credential is
// registrySecret.
func fakePortal(t *testing.T) *portaltest.Server {
	t.Helper()
	return fakePortalWithToken(t, registrySecret)
}

// fakePortalWithToken starts a fake portal whose registry credential is
// token.
func fakePortalWithToken(t *testing.T, token string) *portaltest.Server {
	t.Helper()
	return portaltest.New(t, portaltest.Options{
		Tenant:   wire.Tenant{Subdomain: "acme", AccountRef: "ACME-1"},
		Registry: "https://registry.example.test",
		RegistryCredential: &wire.RegistryCredential{
			Contract: wire.Contract, Registry: "https://registry.example.test",
			Username: "acme", Token: token, Source: "staff",
		},
	})
}

// hermeticEnv is a process environment with every SECURECHAIN_*, TUXCARE_*,
// GITHUB_*, RUNNER_* variable and every CI marker (internal/client/auth.
// CIMarkers) removed, so an ambient build agent or a developer's own login
// cannot leak into what the script sees. extra is then added on top.
func hermeticEnv(bin string, extra map[string]string) []string {
	// The npm and netrc variables name the files registry env copies, and
	// XDG_CONFIG_HOME where bun reads; on a developer's machine or a CI
	// runner those are outside the test.
	drop := map[string]bool{"HOME": true, "XDG_CONFIG_HOME": true, "USERPROFILE": true, "PATH": true,
		"NPM_CONFIG_USERCONFIG": true, "npm_config_userconfig": true, "NETRC": true,
		"NPM_CONFIG_REGISTRY": true, "npm_config_registry": true}
	for _, m := range auth.CIMarkers() {
		drop[m] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if drop[k] || toolVariable(k) || strings.HasPrefix(k, "SECURECHAIN_") || strings.HasPrefix(k, "TUXCARE_") ||
			strings.HasPrefix(k, "GITHUB_") || strings.HasPrefix(k, "RUNNER_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+strings.Join([]string{filepath.Dir(bin), fakeNpmDir, os.Getenv("PATH")}, string(os.PathListSeparator)))
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// job is the environment of one GitHub job: HOME, RUNNER_TEMP, $GITHUB_ENV
// and $GITHUB_OUTPUT in the test's own directories, and a portal.
type job struct {
	home, runnerTemp, githubEnv, githubOutput string
	vars                                      map[string]string
}

func newJob(t *testing.T, srv *portaltest.Server, login, command string) *job {
	t.Helper()
	j := &job{home: t.TempDir(), runnerTemp: t.TempDir()}
	j.githubEnv = filepath.Join(t.TempDir(), "github_env")
	j.githubOutput = filepath.Join(t.TempDir(), "github_output")
	j.vars = map[string]string{
		"HOME":                     j.home,
		"SECURECHAIN_CACHE":        t.TempDir(),
		"SECURECHAIN_PORTAL_URL":   srv.URL,
		"SECURECHAIN_PORTAL_TOKEN": "sctest_faketoken",
		"REGISTRY_LOGIN":           login,
		"COMMAND":                  command,
		"DIR":                      ".",
		"SARIF":                    "true",
		"ARGS":                     "",
		"RUNNER_TEMP":              j.runnerTemp,
		"GITHUB_ENV":               j.githubEnv,
		"GITHUB_OUTPUT":            j.githubOutput,
	}
	return j
}

// run runs script in dir with the job's environment, and returns stdout and
// stderr.
func (j *job) run(t *testing.T, bin, script, dir string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = hermeticEnv(bin, j.vars)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// exported is what the job wrote into $GITHUB_ENV, by name.
func (j *job) exported(t *testing.T) map[string]string {
	t.Helper()
	b, _ := os.ReadFile(j.githubEnv)
	vars := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vars[k] = v
		}
	}
	return vars
}

// secretOnDisk walks dir and names every file under it holding registrySecret.
func secretOnDisk(t *testing.T, dir string) []string {
	t.Helper()
	var hits []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), registrySecret) {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// Q81 and Q82, decided 28 September 2026: the job directory in RUNNER_TEMP,
// whose variables the later steps read, and no token in the user-level
// files.
func TestActionWritesTheJobDirectoryExportsItsVariablesAndMasksThem(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err != nil {
		t.Fatalf("the action's registry-credential step failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	jobDir := filepath.Join(j.runnerTemp, "securechain-job")
	want := map[string]string{
		"TUXCARE_TOKEN":         registrySecret,
		"TUXCARE_REGISTRY_USER": "acme",
		"NPM_CONFIG_USERCONFIG": filepath.Join(jobDir, "npmrc"),
		"npm_config_userconfig": filepath.Join(jobDir, "npmrc"),
		"NETRC":                 filepath.Join(jobDir, "netrc"),
	}
	got := j.exported(t)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("$GITHUB_ENV %s = %q, want %q", k, got[k], v)
		}
		if !strings.Contains(stdout, "::add-mask::"+v+"\n") {
			t.Errorf("the value of %s was exported without its mask line", k)
		}
	}
	for _, f := range []string{"npmrc", "netrc"} {
		if b, err := os.ReadFile(filepath.Join(jobDir, f)); err != nil || !strings.Contains(string(b), registrySecret) {
			t.Errorf("the job's %s does not carry the token: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(j.runnerTemp, "securechain.env")); !os.IsNotExist(err) {
		t.Errorf("the temporary env file was not removed: stat error = %v", err)
	}
	if hits := secretOnDisk(t, j.home); len(hits) > 0 {
		t.Errorf("the job directory route left the token under HOME: %v", hits)
	}
	if entries, _ := os.ReadDir(j.home); len(entries) != 0 {
		t.Errorf("an npm project's credential step wrote %d entries under HOME", len(entries))
	}
}

// The two routes before 28 September 2026 wrote user-level files:
// `reference` left a ${TUXCARE_TOKEN} line in ~/.npmrc that stops yarn
// classic, and `plain` left the token in ~/.npmrc and ~/.netrc (doc 99 Q81,
// Q82). A workflow that still names one stops with the two values that
// remain.
func TestActionRefusesARegistryLoginValueOtherThanJobDirAndNone(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, value := range []string{"bogus", "reference", "plain"} {
		t.Run(value, func(t *testing.T) {
			srv := fakePortal(t)
			j := newJob(t, srv, value, "check")
			stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
			if err == nil {
				t.Fatalf("registry-login: %s must fail the step; output:\n%s%s", value, stdout, stderr)
			}
			if !strings.Contains(stdout, "'job-dir' or 'none'") {
				t.Errorf("the failure does not name both values:\n%s", stdout)
			}
			if n := len(srv.Requests()); n != 0 {
				t.Errorf("registry-login: %s sent %d requests to the portal", value, n)
			}
			if entries, _ := os.ReadDir(j.home); len(entries) != 0 {
				t.Errorf("registry-login: %s wrote %d entries under HOME", value, len(entries))
			}
		})
	}
}

// Doc 03: yarn berry reads neither variable, so a berry project also gets
// `registry login --reference --ecosystem yarn-berry`, whose ${TUXCARE_TOKEN:-}
// stops no other project. The project is in `dir`, below the workspace, as
// fix round 1 of the portal plan found the step ignoring it.
func TestActionGivesABerryProjectInDirTheReferenceLine(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, tc := range []struct{ name, file, content string }{
		{"a .yarnrc.yml", ".yarnrc.yml", "nodeLinker: node-modules\n"},
		{"a berry yarn.lock", "yarn.lock", "# This file is generated by running \"yarn install\"\n\n__metadata:\n  version: 8\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace := t.TempDir()
			sub := filepath.Join(workspace, "sub")
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sub, tc.file), []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			j := newJob(t, fakePortal(t), "job-dir", "registry")
			j.vars["DIR"] = "sub"
			stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), workspace)
			if err != nil {
				t.Fatalf("the step failed: %v\n%s%s", err, stdout, stderr)
			}
			b, rerr := os.ReadFile(filepath.Join(j.home, ".yarnrc.yml"))
			if rerr != nil || !strings.Contains(string(b), "${TUXCARE_TOKEN:-}") {
				t.Errorf("~/.yarnrc.yml = %q, %v; want the reference", b, rerr)
			}
			// Ruling D-R2: the templates do not put ~/.yarnrc.yml back, so the
			// berry step must not change berry's source there.
			if strings.Contains(string(b), "npmRegistryServer") {
				t.Errorf("the berry step changed berry's source:\n%s", b)
			}
			if !strings.Contains(registryCredentialScript(t), "--reference --keep-source --ecosystem yarn-berry") {
				t.Error("the berry step does not run registry login with --keep-source")
			}
			if hits := secretOnDisk(t, j.home); len(hits) > 0 {
				t.Errorf("the berry step left the token under HOME: %v", hits)
			}
			// L2 of the review of 29 September 2026: the berry step records
			// the lines it adds, as bun's does, and the last step's registry
			// end removes them. Before, a reference one job left sent a later
			// job's token through a project's proxy.
			if script := strings.Join(strings.Fields(registryCredentialScript(t)), " "); !strings.Contains(script,
				`--ecosystem yarn-berry \ --job-dir "$jobdir" --job-process "$PPID"`) {
				t.Error("the berry step does not pass the job directory and the job's process")
			}
			if stdout, stderr, err := j.run(t, bin, cleanupScript(t), workspace); err != nil {
				t.Fatalf("the last step failed: %v\n%s%s", err, stdout, stderr)
			}
			if b, _ := os.ReadFile(filepath.Join(j.home, ".yarnrc.yml")); strings.Contains(string(b), "TUXCARE_TOKEN") {
				t.Errorf("the last step left the reference in ~/.yarnrc.yml:\n%s", b)
			}
		})
	}
}

// Q91, decided 28 September 2026: bun reads neither variable, and its token
// variables reach a host that bun.lock names (doc 07). So the login writes
// the key into bun's .npmrc, and the last step removes the lines the step
// added (ruling D-R60): the user's own lines stay byte for byte, and the
// file keeps the mode 0600 that the login gave it (doc 03).
func TestActionGivesABunProjectTheKeyAndTheLastStepRemovesItsLines(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, tc := range []struct {
		name     string
		xdg      bool // XDG_CONFIG_HOME set: bun reads its .npmrc there
		before   string
		lockfile string
		content  string
		give     bool // Q93: bun gets the key only for a clean bun.lock
	}{
		{"bun.lock, a ~/.npmrc of the user's", false, "fund=false\n", "bun.lock", cleanBunLock, true},
		{"bun.lock, no ~/.npmrc", false, "", "bun.lock", cleanBunLock, true},
		{"XDG_CONFIG_HOME", true, "fund=false\n", "bun.lock", cleanBunLock, true},
		{"bun.lock names another host", false, "fund=false\n", "bun.lock", foreignBunLock, false},
		{"only bun.lockb", false, "", "bun.lockb", "#!/usr/bin/env bun\nbun-lockfile-format-v0\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakePortal(t)
			project := projectWith(t, tc.lockfile, tc.content)
			j := newJob(t, srv, "job-dir", "registry")
			bunrc := filepath.Join(j.home, ".npmrc")
			if tc.xdg {
				xdg := t.TempDir()
				j.vars["XDG_CONFIG_HOME"] = xdg
				bunrc = filepath.Join(xdg, ".npmrc")
			}
			if tc.before != "" {
				if err := os.WriteFile(bunrc, []byte(tc.before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project)
			if err != nil {
				t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			b, err := os.ReadFile(bunrc)
			keyed := err == nil && strings.Contains(string(b), "//registry.example.test/npm/:_authToken="+registrySecret)
			if keyed != tc.give {
				t.Fatalf("bun's .npmrc = %q, %v; want the key written: %v\n%s", b, err, tc.give, stdout)
			}
			if !tc.give && !strings.Contains(stdout, "nothing written for bun: bun: ") {
				t.Errorf("the step does not say why bun got nothing:\n%s", stdout)
			}

			// The gate's use: its last step runs with registry-login: none.
			j.vars["REGISTRY_LOGIN"], j.vars["COMMAND"] = "none", "check"
			if stdout, stderr, err := j.run(t, bin, cleanupScript(t), project); err != nil {
				t.Fatalf("the last step failed: %v\n%s%s", err, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(j.runnerTemp, "securechain-job")); !os.IsNotExist(err) {
				t.Errorf("the job directory is still there: %v", err)
			}
			b, err = os.ReadFile(bunrc)
			switch {
			case tc.before == "" && !os.IsNotExist(err):
				t.Errorf("bun's .npmrc, which the login created, is still there: %q, %v", b, err)
			case tc.before != "" && string(b) != tc.before:
				t.Errorf("bun's .npmrc = %q, %v; want %q back", b, err, tc.before)
			case tc.before != "" && tc.give:
				if info, _ := os.Stat(bunrc); info.Mode().Perm() != 0o600 {
					t.Errorf("bun's .npmrc has mode %v after the job, want the 0600 the login gave it", info.Mode().Perm())
				}
			case tc.before != "":
				if info, _ := os.Stat(bunrc); info.Mode().Perm() != 0o644 {
					t.Errorf("bun's .npmrc, which the step did not write, has mode %v, want 0644", info.Mode().Perm())
				}
			}
			if n := len(srv.Requests()); n == 0 {
				t.Error("the portal was asked nothing")
			}
		})
	}
}

// The last step runs where the job directory is done with: in the gate's
// use, whatever the steps before it did, and in `command: registry` only when
// that use failed, because the customer's install step still reads it.
func TestTheLastStepRunsAlwaysButNotAfterASuccessfulCommandRegistry(t *testing.T) {
	_, cond := namedStep(t, "Remove the job directory")
	if cond != "always() && (inputs.command != 'registry' || failure())" {
		t.Errorf("the last step's if: is %q", cond)
	}
	steps := actionSteps(t).Runs.Steps
	if steps[len(steps)-1].Name != "Remove the job directory" {
		t.Errorf("the last step is %q", steps[len(steps)-1].Name)
	}
}

// A last step with no record of the lines a credential step added changes
// nothing in bun's .npmrc: it removes only what the list names.
func TestTheLastStepLeavesBunsFileWithNoRecordOfAddedLines(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "none", "check")
	jobDir := filepath.Join(j.runnerTemp, "securechain-job")
	if err := os.Mkdir(jobDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bunrc := filepath.Join(j.home, ".npmrc")
	if err := os.WriteFile(bunrc, []byte("fund=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.run(t, bin, cleanupScript(t), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(bunrc); err != nil || string(b) != "fund=false\n" {
		t.Errorf("~/.npmrc = %q, %v; the last step changed it with no record of added lines", b, err)
	}
}

// End-to-end for fix round 2, item 4: the fake portal's registry credential
// carries a user name with a newline. internal/client/portal/routes.go now
// refuses it (a byte a token cannot carry is not safe in a user name
// either, doc 19 §9) before `registry env` could ever print it, so the step
// must fail closed exactly like a portal outage - and $GITHUB_ENV must hold
// neither TUXCARE_TOKEN nor the injected key.
func TestActionRefusesAUserNameThatCouldInjectAVariable(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv := portaltest.New(t, portaltest.Options{
		Tenant:   wire.Tenant{Subdomain: "acme", AccountRef: "ACME-1"},
		Registry: "https://registry.example.test",
		RegistryCredential: &wire.RegistryCredential{
			Contract: wire.Contract, Registry: "https://registry.example.test",
			Username: "acme\nGITHUB_TOKEN=evil", Token: registrySecret, Source: "staff",
		},
	})
	j := newJob(t, srv, "job-dir", "check")
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err == nil {
		t.Fatalf("a user name that could inject a variable must fail the step; output:\n%s%s", stdout, stderr)
	}
	if b, err := os.ReadFile(j.githubEnv); err == nil {
		if strings.Contains(string(b), "TUXCARE_TOKEN") {
			t.Errorf("$GITHUB_ENV must not carry TUXCARE_TOKEN when the user name is refused:\n%s", b)
		}
		if strings.Contains(string(b), "GITHUB_TOKEN") {
			t.Errorf("$GITHUB_ENV carries the injected key:\n%s", b)
		}
	}
}

// Regression: fix round 1 found `securechain registry env > file` was
// believed but never checked to fail the step. A portal that refuses the
// registry credential fails `registry env`, the first request for it, and
// the step stops before $GITHUB_ENV is written: unlike GitLab's `eval
// "$(...)"`, a redirected command's own exit status is not swallowed by
// set -e.
func TestActionFailsClosedWhenThePortalCannotAnswer(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv := fakePortal(t)
	srv.Fault = func(path string) (int, string, bool) {
		if path == "/securechain/v1/registry-credential" {
			return 503, `{"reason":"boom"}`, true
		}
		return 0, "", false
	}
	j := newJob(t, srv, "job-dir", "check")
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err == nil {
		t.Fatalf("a portal that answers 503 on registry-credential must fail the step; output:\n%s%s", stdout, stderr)
	}
	if b, err := os.ReadFile(j.githubEnv); err == nil && len(b) > 0 {
		t.Errorf("$GITHUB_ENV must stay empty when the portal failed:\n%s", b)
	}
}

// A bun project's login is the step's last request: when it fails, the step
// fails, and the last step, which runs on that failure, puts the file back.
func TestActionFailsWhenTheBunLoginFailsAndTheLastStepLeavesTheFileAsItWas(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv := fakePortal(t)
	var calls int32
	srv.Fault = func(path string) (int, string, bool) {
		if path != "/securechain/v1/registry-credential" {
			return 0, "", false
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			return 0, "", false // registry env's own call: let it succeed
		}
		return 503, `{"reason":"boom"}`, true // the bun login's call: fail it
	}
	j := newJob(t, srv, "job-dir", "registry")
	bunrc := filepath.Join(j.home, ".npmrc")
	if err := os.WriteFile(bunrc, []byte("fund=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := projectWith(t, "bun.lock", "{}\n")
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err == nil {
		t.Fatalf("a failed bun login must fail the step; output:\n%s%s", stdout, stderr)
	}
	if _, _, err := j.run(t, bin, cleanupScript(t), project); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(bunrc); err != nil || string(b) != "fund=false\n" {
		t.Errorf("~/.npmrc = %q, %v; want it as it was", b, err)
	}
	if _, err := os.Stat(filepath.Join(j.runnerTemp, "securechain-job")); !os.IsNotExist(err) {
		t.Errorf("the job directory is still there: %v", err)
	}
}

// Review of the portal-only branch, area 4 (M8): both templates always ran
// registry login, so a tenant whose registry credential nobody had set yet
// (stage 1) got exit 3 before check, which needs no credential (doc 19 §9).
func TestActionRegistryLoginNoneWritesNothingAndAsksThePortalForNothing(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv := portaltest.New(t, portaltest.Options{ // no registry credential
		Tenant:   wire.Tenant{Subdomain: "acme", AccountRef: "ACME-1"},
		Registry: "https://registry.example.test",
	})
	j := newJob(t, srv, "none", "check")
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err != nil {
		t.Fatalf("registry-login: none failed: %v\n%s%s", err, stdout, stderr)
	}
	if b, err := os.ReadFile(j.githubEnv); err == nil && len(b) > 0 {
		t.Errorf("registry-login: none exported %q", b)
	}
	if entries, _ := os.ReadDir(j.home); len(entries) != 0 {
		t.Errorf("registry-login: none wrote %d entries under HOME", len(entries))
	}
	if entries, _ := os.ReadDir(j.runnerTemp); len(entries) != 0 {
		t.Errorf("registry-login: none wrote %d entries under RUNNER_TEMP", len(entries))
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("registry-login: none sent %d requests to the portal", n)
	}
}

// command: registry with registry-login: none would write nothing and run
// no gate: a step that does nothing and passes.
func TestActionRefusesCommandRegistryWithRegistryLoginNone(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "none", "registry")
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err == nil {
		t.Fatalf("command: registry with registry-login: none must fail the step; output:\n%s%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "registry") || !strings.Contains(stdout, "none") {
		t.Errorf("the failure does not name the two inputs:\n%s", stdout)
	}
}

// Review of the portal-only branch, area 4 (I4), measured: `check` on an npm
// project with no install exits 5, so the documented flow ran `npm ci`
// before the action, with no credential. `command: registry` writes the
// credential for a later install step and runs no gate; before it, the run
// step ran `securechain registry` and recorded exit 2.
func TestActionCommandRegistryExportsTheCredentialAndRunsNoGate(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	srv := fakePortal(t)
	project := npmProject(t)
	j := newJob(t, srv, "job-dir", "registry")
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
		t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	if got := j.exported(t)["TUXCARE_TOKEN"]; got != registrySecret {
		t.Errorf("$GITHUB_ENV does not carry TUXCARE_TOKEN for the later install step: %q", got)
	}
	before := len(srv.Requests())

	stdout, stderr, err := j.run(t, bin, runStepScript(t), project)
	if err != nil {
		t.Fatalf("the run step failed: %v\n%s%s", err, stdout, stderr)
	}
	b, _ := os.ReadFile(j.githubOutput)
	if !strings.Contains(string(b), "exit-code=0\n") || strings.Contains(string(b), "sarif-file") {
		t.Errorf("$GITHUB_OUTPUT = %q, want exit-code=0 and no SARIF file\n%s", b, stdout)
	}
	if n := len(srv.Requests()) - before; n != 0 {
		t.Errorf("the run step sent %d requests to the portal: a gate ran", n)
	}
}

// Found by the re-review of fix F4, 27 September 2026, in bash 3.2 and
// dash: `while IFS='=' read -r key value` reads `K=abc=` as `abc`, one
// trailing '=' dropped. auth.NewToken accepts '=', so a base64 registry
// token that ends in '=' was masked and exported short, and the install
// sent a wrong token.
func TestActionExportsATokenThatEndsInEqualsSignsWhole(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	script := registryCredentialScript(t)
	for _, token := range []string{"cmVnLXQwa2Vu=", "cmVnLXQwaw=="} {
		t.Run(token, func(t *testing.T) {
			j := newJob(t, fakePortalWithToken(t, token), "job-dir", "check")
			stdout, stderr, err := j.run(t, bin, script, npmProject(t))
			if err != nil {
				t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			b, _ := os.ReadFile(j.githubEnv)
			if !strings.Contains(string(b), "TUXCARE_TOKEN="+token+"\n") {
				t.Errorf("$GITHUB_ENV = %q, want TUXCARE_TOKEN=%s whole", b, token)
			}
			if !strings.Contains(stdout, "::add-mask::"+token+"\n") {
				t.Errorf("the mask line does not carry %s whole:\n%s", token, stdout)
			}
		})
	}
}

// Critical 2 of the review of 28 September 2026: a workflow can run the
// credential step twice, `command: registry` and then the gate with
// `registry-login: job-dir`. The second run copied bun's .npmrc, which then
// held the token, over the first copy, and the last step put the token back
// into ~/.npmrc. Since ruling D-R60 no copy is kept: the second run adds the
// lines it added to the list, and the last step removes them all.
func TestActionASecondCredentialStepAddsItsLinesToTheList(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, before := range []string{"fund=false\n", ""} {
		t.Run("before "+strings.TrimSpace(before), func(t *testing.T) {
			srv := fakePortal(t)
			project := projectWith(t, "bun.lock", cleanBunLock)
			j := newJob(t, srv, "job-dir", "registry")
			bunrc := filepath.Join(j.home, ".npmrc")
			if before != "" {
				if err := os.WriteFile(bunrc, []byte(before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
				t.Fatalf("the first credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			// The gate's use, with the credential step again.
			j.vars["COMMAND"] = "check"
			if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
				t.Fatalf("the second credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			if b, _ := os.ReadFile(bunrc); !strings.Contains(string(b), registrySecret) {
				t.Fatalf("bun's .npmrc lost the key: %q", b)
			}
			if _, _, err := j.run(t, bin, cleanupScript(t), project); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(bunrc)
			switch {
			case before == "" && !os.IsNotExist(err):
				t.Errorf("bun's .npmrc is still there after the job: %q, %v", b, err)
			case before != "" && string(b) != before:
				t.Errorf("bun's .npmrc = %q after the job, want %q", b, before)
			}
			if hits := secretOnDisk(t, j.home); len(hits) > 0 {
				t.Errorf("the token stayed under HOME: %v", hits)
			}
		})
	}
}

// A symbolic link at bun's .npmrc, dangling or not: the step writes nothing
// through it, says so in one line, and the link and its target stay as they
// were (doc 03).
func TestActionWritesNothingThroughASymbolicLinkAtBunsFile(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, dangling := range []bool{false, true} {
		t.Run(fmt.Sprintf("dangling %v", dangling), func(t *testing.T) {
			project := projectWith(t, "bun.lock", cleanBunLock)
			j := newJob(t, fakePortal(t), "job-dir", "registry")
			target := filepath.Join(t.TempDir(), "dotfiles-npmrc")
			if !dangling {
				if err := os.WriteFile(target, []byte("fund=false\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			bunrc := filepath.Join(j.home, ".npmrc")
			if err := os.Symlink(target, bunrc); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project)
			if err != nil {
				t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			if !strings.Contains(stdout, "is a symbolic link") {
				t.Errorf("the step does not say why bun got nothing:\n%s", stdout)
			}
			j.vars["COMMAND"] = "check"
			if _, _, err := j.run(t, bin, cleanupScript(t), project); err != nil {
				t.Fatal(err)
			}
			if link, err := os.Readlink(bunrc); err != nil || link != target {
				t.Errorf("the link is now %q, %v", link, err)
			}
			b, err := os.ReadFile(target)
			if dangling != os.IsNotExist(err) || (!dangling && string(b) != "fund=false\n") {
				t.Errorf("the link's target = %q, %v", b, err)
			}
		})
	}
}

// I2 of the final review, measured 28 September 2026 through the Action's
// steps on one HOME in the order A's credential step, B's, A's last step,
// B's last step: B's copy of bun's .npmrc held A's token, and B's last step
// put the token, the registry line and always-auth back after both jobs.
// Ruling D-R60: each last step removes only the lines its own steps added.
// A line of the same text that the other job needs may go too, which that
// job sees as a 401; no token line may stay.
func TestTwoJobsOnOneHomeLeaveNoTokenInBunsFile(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	const otherSecret = "sctok_second_job_token_000000000000"
	for _, tc := range []struct {
		name   string
		tokenB string
		before string
	}{
		{"one token, no file before", registrySecret, ""},
		{"one token, a file of the user's", registrySecret, "fund=false\n"},
		{"two tokens, a file of the user's", otherSecret, "fund=false\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := projectWith(t, "bun.lock", cleanBunLock)
			a := newJob(t, fakePortal(t), "job-dir", "check")
			b := newJob(t, fakePortalWithToken(t, tc.tokenB), "job-dir", "check")
			b.home, b.vars["HOME"] = a.home, a.home
			bunrc := filepath.Join(a.home, ".npmrc")
			if tc.before != "" {
				if err := os.WriteFile(bunrc, []byte(tc.before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for i, step := range []struct {
				j      *job
				script string
			}{
				{a, registryCredentialScript(t)}, {b, registryCredentialScript(t)},
				{a, cleanupScript(t)}, {b, cleanupScript(t)},
			} {
				if stdout, stderr, err := step.j.run(t, bin, step.script, project); err != nil {
					t.Fatalf("a step failed: %v\n%s%s", err, stdout, stderr)
				}
				if i == 1 {
					if got, _ := os.ReadFile(bunrc); !strings.Contains(string(got), ":_authToken=") {
						t.Fatalf("after both credential steps bun's .npmrc holds no key, so the test measures nothing: %q", got)
					}
				}
			}
			got, err := os.ReadFile(bunrc)
			switch {
			case tc.before == "" && !os.IsNotExist(err):
				t.Errorf("bun's .npmrc is still there after both jobs: %q, %v", got, err)
			case tc.before != "" && string(got) != tc.before:
				t.Errorf("bun's .npmrc = %q after both jobs, want %q", got, tc.before)
			}
			for _, secret := range []string{registrySecret, otherSecret} {
				if strings.Contains(string(got), secret) {
					t.Errorf("a token stayed in bun's .npmrc: %q", got)
				}
			}
		})
	}
}

// M1 of the final review: `command: registry` runs no last step, so bun's
// key stays in its .npmrc until the gate's use of the action ends, and the
// job log said nothing. The step now prints a notice when it wrote the key.
func TestCommandRegistryNoticesThatBunsKeyStaysUntilTheGatesUse(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, tc := range []struct {
		name, command, lock string
		notice              bool
	}{
		{"command: registry, bun gets the key", "registry", cleanBunLock, true},
		{"command: registry, bun gets nothing", "registry", foreignBunLock, false},
		{"the gate's use", "check", cleanBunLock, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newJob(t, fakePortal(t), "job-dir", tc.command)
			stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), projectWith(t, "bun.lock", tc.lock))
			if err != nil {
				t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			line := "::notice::securechain: bun's registry key is in " + filepath.Join(j.home, ".npmrc")
			if got := strings.Contains(stdout, line); got != tc.notice {
				t.Errorf("the notice printed: %v, want %v\n%s", got, tc.notice, stdout)
			}
			if tc.notice && !strings.Contains(stdout, "if: always()") {
				t.Errorf("the notice does not say how the key is removed:\n%s", stdout)
			}
		})
	}
}

// toolVariable reports whether k changes what a package manager, or the
// binary's own source rule, reads: the configuration variables of npm,
// pnpm, bun and yarn in any case, the proxy variables, and
// registrycred.SourceVariables. hermeticEnv drops each one. M4 of the final
// review of 28 September 2026 measured that BUN_CONFIG_REGISTRY in the
// machine's environment failed the bun tests here: bun's default registry
// was the variable's, and the step refused bun.
func toolVariable(k string) bool {
	lower := strings.ToLower(k)
	for _, prefix := range []string{"npm_config_", "pnpm_config_", "bun_config_", "yarn_"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	switch lower {
	case "http_proxy", "https_proxy", "no_proxy", "all_proxy":
		return true
	}
	for _, v := range registrycred.SourceVariables {
		if strings.EqualFold(k, v) {
			return true
		}
	}
	return false
}

// Ruling D-R61, I4 of the final review: the job's variables take the proxy
// and the TLS check from the user's own settings, and outrank a project
// .npmrc. Since ruling N7 they are set only for a project file that
// names a proxy. The step exports them, and masks no `true`, `false` or `null`: a
// mask of such a word would hide it in every later line of the log.
func TestActionExportsTheTransportVariablesWithoutMaskingTheirWords(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	j.vars["HTTPS_PROXY"] = "http://corp.example:3128"
	project := npmProject(t)
	if err := os.WriteFile(filepath.Join(project, ".npmrc"), []byte("https-proxy=http://evil.example:3128\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project)
	if err != nil {
		t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	want := map[string]string{
		"npm_config_strict_ssl": "true", "pnpm_config_strict_ssl": "true",
		"npm_config_https_proxy": "http://corp.example:3128", "npm_config_proxy": "http://corp.example:3128",
		"pnpm_config_https_proxy": "http://corp.example:3128", "pnpm_config_proxy": "http://corp.example:3128",
	}
	got := j.exported(t)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("$GITHUB_ENV %s = %q, want %q", k, got[k], v)
		}
	}
	for _, word := range []string{"true", "false", "null"} {
		if strings.Contains(stdout, "::add-mask::"+word+"\n") {
			t.Errorf("the step masked %q:\n%s", word, stdout)
		}
	}
	if !strings.Contains(stdout, "::add-mask::http://corp.example:3128\n") {
		t.Errorf("the proxy URL, which can carry a password, was not masked:\n%s", stdout)
	}
}

// runUnderAWorkerThatEnds runs script as a step whose parent, the runner's
// process for the job, ends with the step: a job killed after this step.
func (j *job) runUnderAWorkerThatEnds(t *testing.T, bin, script, dir string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	// "; true" keeps the outer shell as the step's parent until the step
	// ends; then it ends too.
	cmd := exec.Command("bash", "-c", `bash --noprofile --norc -eo pipefail "$0"; true`, path)
	cmd.Dir = dir
	cmd.Env = hermeticEnv(bin, j.vars)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// N3 of the review of 28 September 2026, ruling D-R67: a job killed between
// its credential step and its end left the registry line, the key and
// always-auth=true in ~/.npmrc for good when the token did not change, and
// each later job read them as the user's own. Measured with one and two
// killed jobs on one HOME. The next job's credential step removes a dead
// job's lines, names them, and that job's end leaves the user's file alone.
func TestAJobKilledBeforeItsEndLeavesNoTokenAfterTheNextJob(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	for _, killed := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d killed", killed), func(t *testing.T) {
			home := t.TempDir()
			bunrc := filepath.Join(home, ".npmrc")
			if err := os.WriteFile(bunrc, []byte("fund=false\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			project := projectWith(t, "bun.lock", cleanBunLock)
			for i := 0; i < killed; i++ {
				k := newJob(t, fakePortal(t), "job-dir", "check")
				k.home, k.vars["HOME"] = home, home
				if out, err := k.runUnderAWorkerThatEnds(t, bin, registryCredentialScript(t), project); err != nil {
					t.Fatalf("killed job %d's credential step failed: %v\n%s", i, err, out)
				}
			}
			if b, _ := os.ReadFile(bunrc); !strings.Contains(string(b), registrySecret) {
				t.Fatalf("the killed jobs wrote no key, so the test measures nothing: %q", b)
			}
			z := newJob(t, fakePortal(t), "job-dir", "check")
			z.home, z.vars["HOME"] = home, home
			stdout, stderr, err := z.run(t, bin, registryCredentialScript(t), project)
			if err != nil {
				t.Fatalf("the next job's credential step failed: %v\n%s%s", err, stdout, stderr)
			}
			if !strings.Contains(stdout, "left when it ended without its last step") {
				t.Errorf("the step does not name the dead job's lines it removed:\n%s", stdout)
			}
			if b, _ := os.ReadFile(bunrc); !strings.Contains(string(b), registrySecret) {
				t.Fatalf("the next job's step left bun without a key: %q", b)
			}
			if stdout, stderr, err := z.run(t, bin, cleanupScript(t), project); err != nil {
				t.Fatalf("the last step failed: %v\n%s%s", err, stdout, stderr)
			}
			if b, _ := os.ReadFile(bunrc); string(b) != "fund=false\n" {
				t.Errorf("bun's .npmrc = %q after the next job, want the user's line alone", b)
			}
			if hits := secretOnDisk(t, home); len(hits) > 0 {
				t.Errorf("the token stayed under HOME: %v", hits)
			}
		})
	}
}

// Ruling B2 (the review of 29 September 2026): a step between the
// credential step and the last one wrote XDG_CONFIG_HOME to $GITHUB_ENV, and
// the last step exited 0 with nothing printed while ~/.npmrc kept the
// registry line, the key and always-auth. registry end now cleans the file
// that the job directory names.
func TestTheLastStepCleansBunsFileAfterAStepExportedXDGConfigHome(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	project := projectWith(t, "bun.lock", cleanBunLock)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	bunrc := filepath.Join(j.home, ".npmrc")
	if err := os.WriteFile(bunrc, []byte("fund=false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
		t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	if b, _ := os.ReadFile(bunrc); !strings.Contains(string(b), registrySecret) {
		t.Fatalf("no key was written, so the test measures nothing: %q", b)
	}
	j.vars["XDG_CONFIG_HOME"] = t.TempDir() // a later step's export
	j.vars["COMMAND"] = "check"
	stdout, stderr, err := j.run(t, bin, cleanupScript(t), project)
	if err != nil {
		t.Fatalf("the last step failed: %v\n%s%s", err, stdout, stderr)
	}
	if b, _ := os.ReadFile(bunrc); string(b) != "fund=false\n" {
		t.Errorf("~/.npmrc = %q after the job, want the user's line alone\n%s%s", b, stdout, stderr)
	}
}

// A value of several lines reaches $GITHUB_ENV in the form it takes for one,
// whole, and adds no variable of its own. No variable the job prints holds
// one since ruling D-R72; a proxy of the user's could.
func TestTheStepCopiesAValueOfSeveralLinesWhole(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	j.vars["HTTPS_PROXY"] = "http://corp.example:3128\nINJECTED=1"
	stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t))
	if err != nil {
		t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	env, _ := os.ReadFile(j.githubEnv)
	i := strings.Index(string(env), "npm_config_https_proxy<<SECURECHAIN_EOF_")
	if i < 0 {
		t.Fatalf("$GITHUB_ENV has no block for the value:\n%s", env)
	}
	first, rest, _ := strings.Cut(string(env)[i:], "\n")
	delim := strings.TrimPrefix(first, "npm_config_https_proxy<<")
	if !strings.HasPrefix(rest, "http://corp.example:3128\nINJECTED=1\n"+delim+"\n") {
		t.Errorf("the block is not the value then its delimiter:\n%s", string(env)[i:])
	}
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "INJECTED=") && !strings.Contains(string(env)[i:], "INJECTED=1\n"+delim) {
			t.Errorf("the value added a variable of its own:\n%s", env)
		}
	}
	if !strings.Contains(string(env), "pnpm_config_proxy<<SECURECHAIN_EOF_") {
		t.Errorf("$GITHUB_ENV lost the lines after the block:\n%s", env)
	}
}

// Ruling D-R72 (C1 of the review of 29 September 2026): with a system CA
// bundle as the user's cafile, the step exported its text, and in GitHub
// every later step, the cleanup too, stopped with `exec /usr/bin/bash:
// argument list too long`. The step exports no CA variable and no long value.
func TestTheStepExportsNoCertificateAuthority(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	bundle := strings.Repeat("-----BEGIN CERTIFICATE-----\nMIIBcorp=\n-----END CERTIFICATE-----\n", 6000)
	if err := os.WriteFile(filepath.Join(j.home, "bundle.pem"), []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.home, ".npmrc"), []byte("cafile="+filepath.Join(j.home, "bundle.pem")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), npmProject(t)); err != nil {
		t.Fatalf("the credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	env, _ := os.ReadFile(j.githubEnv)
	if len(env) > 8192 || strings.Contains(string(env), "BEGIN CERTIFICATE") || strings.Contains(string(env), "_ca") {
		t.Errorf("$GITHUB_ENV holds %d bytes, or a CA:\n%.400s", len(env), env)
	}
}

// Ruling C2 (the review of 29 September 2026): the gate's use of the action,
// at its default registry-login: job-dir, ran a second login after
// XDG_CONFIG_HOME changed; it replaced the job's one entry, the last step
// cleaned the second file only and exited 0, and ~/.npmrc kept the registry
// line, the key and always-auth. Each login now adds its file to the list.
func TestTheLastStepCleansTheFileOfEachLoginOfTheJob(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	project := projectWith(t, "bun.lock", cleanBunLock)
	j := newJob(t, fakePortal(t), "job-dir", "registry")
	first := filepath.Join(j.home, ".npmrc")
	if err := os.WriteFile(first, []byte("fund=false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
		t.Fatalf("the first credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	xdg := t.TempDir()
	j.vars["XDG_CONFIG_HOME"], j.vars["COMMAND"] = xdg, "check"
	if stdout, stderr, err := j.run(t, bin, registryCredentialScript(t), project); err != nil {
		t.Fatalf("the gate's credential step failed: %v\n%s%s", err, stdout, stderr)
	}
	second := filepath.Join(xdg, ".npmrc")
	for _, f := range []string{first, second} {
		if b, _ := os.ReadFile(f); !strings.Contains(string(b), registrySecret) {
			t.Fatalf("%s holds no key, so the test measures nothing: %q", f, b)
		}
	}
	stdout, stderr, err := j.run(t, bin, cleanupScript(t), project)
	if err != nil {
		t.Fatalf("the last step failed: %v\n%s%s", err, stdout, stderr)
	}
	if b, _ := os.ReadFile(first); string(b) != "fund=false\n" {
		t.Errorf("~/.npmrc = %q after the job, want the user's line alone", b)
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Errorf("$XDG_CONFIG_HOME/.npmrc, which the job created, stayed: %v", err)
	}
	for _, f := range []string{first, second} {
		if !strings.Contains(stdout, f) {
			t.Errorf("the last step does not name %s:\n%s", f, stdout)
		}
	}
}

// Moved from the portal's tasks/todo.md on 5 October 2026: `args` and the
// other inputs went into a run: block as text, so a value holding ', $, ;,
// &, |, () or a backtick ran as shell code. Every input now reaches its step
// through env:, and no run: block holds an expression.
func TestNoRunBlockInterpolatesAnExpression(t *testing.T) {
	for _, s := range actionSteps(t).Runs.Steps {
		if s.Run == "" {
			continue
		}
		if strings.Contains(s.Run, "${{") {
			t.Errorf("the %q step's run: block interpolates %q", s.Name, s.Run)
		}
	}
}

// The same item, measured through the run step: an args value with every
// shell metacharacter reaches the binary as argument words, and runs
// nothing. The first word of each command line is "check", so the fake
// securechain records its argv one word a line.
func TestTheArgsInputIsSplitOnSpacesAndRunsNoShell(t *testing.T) {
	bin := securechainBinaryOrSkip(t)
	j := newJob(t, fakePortal(t), "none", "check")
	j.vars["SARIF"] = "false"
	dir := t.TempDir()
	mark := filepath.Join(dir, "pwned")
	wrapDir := t.TempDir()
	wrapper := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$LOG\"\n"
	if err := os.WriteFile(filepath.Join(wrapDir, "securechain"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	j.vars["PATH"] = wrapDir + string(os.PathListSeparator) + os.Getenv("PATH")
	j.vars["LOG"] = filepath.Join(dir, "argv")
	j.vars["ARGS"] = "--fail-on medium ;touch " + mark + "1 `touch " + mark + "2` $(touch " + mark + "3) --baseline 'b c'"
	stdout, stderr, err := j.run(t, bin, runStepScript(t), npmProject(t))
	if err != nil {
		t.Fatalf("the run step failed: %v\n%s%s", err, stdout, stderr)
	}
	for _, suffix := range []string{"1", "2", "3"} {
		if _, err := os.Stat(mark + suffix); !os.IsNotExist(err) {
			t.Errorf("args ran shell: %s exists", mark+suffix)
		}
	}
	b, err := os.ReadFile(j.vars["LOG"])
	if err != nil {
		t.Fatalf("the run step ran no securechain: %v", err)
	}
	want := "check\n--dir\n.\n--fail-on\nmedium\n;touch\n" + mark + "1\n`touch\n" +
		mark + "2`\n$(touch\n" + mark + "3)\n--baseline\n'b\nc'\n"
	if string(b) != want {
		t.Errorf("securechain's argv was\n%s\nwant\n%s", b, want)
	}
}
