// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	// tagEventCondition is the condition every tag-only release guard carries,
	// so a push to main never trips a version-tag check.
	tagEventCondition = "github.ref_type == 'tag'"
	// mainHeadGuardName is the step that refuses a v* tag cut from any commit
	// other than the protected main head.
	mainHeadGuardName = "Require the tag to point at the protected main head"
	// checkoutStepName and manifestGuardName bracket the main-head guard: the
	// guard needs the checkout's git data and must run before the manifest check.
	checkoutStepName  = "Checkout repository"
	manifestGuardName = "Require the tag to match the manifest version"
)

type releaseStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	If   string            `yaml:"if"`
}

type releaseWorkflow struct {
	Jobs map[string]struct {
		Env   map[string]string `yaml:"env"`
		Steps []releaseStep     `yaml:"steps"`
	} `yaml:"jobs"`
}

func releaseStepIndex(steps []releaseStep, name string) int {
	for i, step := range steps {
		if step.Name == name {
			return i
		}
	}
	return -1
}

// mainHeadGuardProblems returns every way raw lets a v* tag publish from a
// commit other than the protected main head: the image job must check out
// without persisted credentials, then refuse a tag whose commit differs from
// origin/main before the manifest check and before anything is pushed.
func mainHeadGuardProblems(raw []byte) []string {
	var workflow releaseWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		return []string{fmt.Sprintf("release.yml does not parse: %v", err)}
	}
	image, ok := workflow.Jobs["image"]
	if !ok {
		return []string{"no job named image"}
	}
	var problems []string
	if got := image.Env["TAG_NAME"]; got != "${{ github.ref_name }}" {
		problems = append(problems, fmt.Sprintf("job env TAG_NAME = %q, want ${{ github.ref_name }}", got))
	}
	if got := image.Env["IMAGE_NAME"]; got != "${{ github.repository }}" {
		problems = append(problems, fmt.Sprintf("job env IMAGE_NAME = %q, want ${{ github.repository }}", got))
	}
	checkout := releaseStepIndex(image.Steps, checkoutStepName)
	guard := releaseStepIndex(image.Steps, mainHeadGuardName)
	manifest := releaseStepIndex(image.Steps, manifestGuardName)
	switch {
	case checkout < 0:
		problems = append(problems, fmt.Sprintf("no step named %q", checkoutStepName))
	case fmt.Sprint(image.Steps[checkout].With["persist-credentials"]) != "false":
		problems = append(problems, "checkout must set persist-credentials: false")
	}
	if guard < 0 {
		return append(problems, fmt.Sprintf("no step named %q", mainHeadGuardName))
	}
	step := image.Steps[guard]
	if step.If != tagEventCondition {
		problems = append(problems, fmt.Sprintf("main-head guard runs when %q, want only tag events", step.If))
	}
	if got := step.Env["TAG_COMMIT"]; got != "${{ github.sha }}" {
		problems = append(problems, fmt.Sprintf("main-head guard TAG_COMMIT = %q, want ${{ github.sha }}", got))
	}
	for _, want := range []string{
		"git fetch origin main",
		`main_head="$(git rev-parse origin/main)"`,
		`[[ "${TAG_COMMIT}" != "${main_head}" ]]`,
		"not the protected main head",
		"exit 1",
	} {
		if !strings.Contains(step.Run, want) {
			problems = append(problems, "main-head guard lacks "+want)
		}
	}
	if checkout >= 0 && guard < checkout {
		problems = append(problems, "main-head guard runs before the checkout")
	}
	if manifest < 0 {
		problems = append(problems, fmt.Sprintf("no step named %q", manifestGuardName))
	} else if guard > manifest {
		problems = append(problems, "main-head guard runs after the manifest version check")
	}
	for i, s := range image.Steps {
		if fmt.Sprint(s.With["push"]) == "true" && guard > i {
			problems = append(problems, "main-head guard runs after the image is pushed")
		}
	}
	return problems
}

func TestReleaseWorkflowRequiresMainHeadTag(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	if problems := mainHeadGuardProblems(raw); len(problems) > 0 {
		t.Fatalf("release.yml:\n%s", strings.Join(problems, "\n"))
	}
}

// TestReleaseWorkflowMainHeadGuardRejectsViolations feeds the check synthetic
// workflows so it is proven to fail, not only to pass on the checked-in file.
func TestReleaseWorkflowMainHeadGuardRejectsViolations(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	for name, mutate := range map[string]func(string) string{
		"guard step dropped": func(s string) string {
			return strings.Replace(s, mainHeadGuardName, "Some other step", 1)
		},
		"guard runs on every event": func(s string) string {
			return strings.Replace(s, "- name: "+mainHeadGuardName+"\n        if: github.ref_type == 'tag'\n", "- name: "+mainHeadGuardName+"\n", 1)
		},
		"guard compares the wrong commit": func(s string) string {
			return strings.Replace(s, "TAG_COMMIT: ${{ github.sha }}", "TAG_COMMIT: ${{ github.ref }}", 1)
		},
		"guard does not fail": func(s string) string {
			return strings.Replace(s, "            exit 1\n          fi\n      - name: "+manifestGuardName, "            exit 0\n          fi\n      - name: "+manifestGuardName, 1)
		},
		"guard compares against a stale ref": func(s string) string {
			return strings.Replace(s, "git rev-parse origin/main", "git rev-parse HEAD", 1)
		},
		"checkout keeps credentials": func(s string) string {
			return strings.Replace(s, "persist-credentials: false", "persist-credentials: true", 1)
		},
		"tag name env dropped": func(s string) string {
			return strings.Replace(s, "      TAG_NAME: ${{ github.ref_name }}\n", "", 1)
		},
		"image name hardcoded": func(s string) string {
			return strings.Replace(s, "IMAGE_NAME: ${{ github.repository }}", "IMAGE_NAME: eshu-hq/x", 1)
		},
	} {
		mutated := mutate(good)
		if mutated == good {
			t.Fatalf("%s: the mutation did not change the workflow", name)
		}
		if len(mainHeadGuardProblems([]byte(mutated))) == 0 {
			t.Errorf("%s: the gate accepted a violating workflow", name)
		}
	}
}
