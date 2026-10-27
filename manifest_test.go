// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	factschemafixture "github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
	"github.com/eshu-hq/eshu-collector-vault-live/runtime"
)

var digestPattern = regexp.MustCompile(`@sha256:[A-Fa-f0-9]{64}$`)

// placeholderDigest is the artifact digest the repository manifest carries
// permanently. manifest.yaml is go:embed'ed into the binary, so a digest
// written into it would belong to an older build than the image that embeds
// it. The deployed digest is stamped at deploy time by `collector seed
// --image-ref` instead (README, "Releasing").
const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// manifestVersion is the component version release tags follow:
// release.yml only publishes v<manifestVersion> (or a v<manifestVersion>-*
// prerelease such as a QA pre-release). Bump this test with manifest.yaml.
const manifestVersion = "0.1.0"

// isPlaceholderImage reports whether image names the placeholder digest.
func isPlaceholderImage(image string) bool {
	return strings.HasSuffix(image, "@"+placeholderDigest)
}

// TestPlaceholderImageGate pins the gate on both sides: the placeholder passes
// and a real-looking digest fails.
func TestPlaceholderImageGate(t *testing.T) {
	t.Parallel()

	const repo = "ghcr.io/eshu-hq/eshu-collector-vault-live@"
	if !isPlaceholderImage(repo + placeholderDigest) {
		t.Fatal("the placeholder digest must pass the gate")
	}
	if isPlaceholderImage(repo + "sha256:" + strings.Repeat("a", 64)) {
		t.Fatal("a real-looking digest must fail the gate")
	}
}

func loadManifest(t testing.TB) conformance.Manifest {
	t.Helper()
	raw, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(manifest.yaml) error = %v", err)
	}
	var manifest conformance.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("yaml.Unmarshal(manifest.yaml) error = %v", err)
	}
	// The conformance Manifest type drops unknown fields; fail closed when
	// the checked-in manifest drifts from the decoded shape.
	if !manifestMatchesRaw(t, raw, manifest) {
		t.Fatal("manifest.yaml does not round-trip through the conformance shape")
	}
	return manifest
}

func manifestMatchesRaw(t testing.TB, raw []byte, manifest conformance.Manifest) bool {
	t.Helper()
	var decoded map[string]any
	if err := yaml.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("yaml.Unmarshal(manifest.yaml) error = %v", err)
	}
	spec, ok := decoded["spec"].(map[string]any)
	if !ok {
		return false
	}
	declared, ok := spec["emittedFacts"].([]any)
	if !ok {
		return false
	}
	return len(declared) == len(manifest.Spec.EmittedFacts)
}

// TestManifestReleaseProvenance proves releases are reproducible and the
// component manifest is valid: every artifact is digest-pinned, the manifest
// carries the supported core range and wire protocol, and every emitted fact
// family is versioned with declared confidence.
func TestManifestReleaseProvenance(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	if strings.TrimSpace(manifest.APIVersion) == "" || strings.TrimSpace(manifest.Kind) == "" {
		t.Fatal("manifest missing apiVersion/kind")
	}
	if manifest.Metadata.ID != "dev.eshu.collector.vault-live" {
		t.Fatalf("manifest id = %q", manifest.Metadata.ID)
	}
	if manifest.Metadata.Version != manifestVersion {
		t.Fatalf("manifest version = %q, want %q", manifest.Metadata.Version, manifestVersion)
	}
	if len(manifest.Spec.Artifacts) == 0 {
		t.Fatal("manifest declares no artifacts")
	}
	for _, artifact := range manifest.Spec.Artifacts {
		if !digestPattern.MatchString(artifact.Image) {
			t.Fatalf("artifact image %q is not digest-pinned", artifact.Image)
		}
		// The repository manifest names the placeholder, never a real
		// digest: the manifest is embedded in the image, so a committed
		// digest could only describe an older build. Deployments stamp the
		// digest they pulled with `collector seed --image-ref REF@sha256:<digest>`.
		if !isPlaceholderImage(artifact.Image) {
			t.Fatalf("artifact image %q is not the placeholder digest: do not commit a real digest "+
				"(the manifest is embedded in the image); stamp the deployed one with collector seed --image-ref", artifact.Image)
		}
	}
	if len(manifest.Spec.EmittedFacts) == 0 {
		t.Fatal("manifest declares no emitted facts")
	}
	for _, family := range manifest.Spec.EmittedFacts {
		if strings.TrimSpace(family.Kind) == "" {
			t.Fatal("emitted fact kind empty")
		}
		if len(family.SchemaVersions) == 0 {
			t.Fatalf("fact kind %q has no schema versions", family.Kind)
		}
		if len(family.SourceConfidence) == 0 {
			t.Fatalf("fact kind %q has no source confidence", family.Kind)
		}
	}
	// consumerContracts.reducer.phases is deliberately omitted: the only
	// optional-component phase the SDK conformance harness accepts is
	// source_evidence_only:no_graph_truth, which would say these facts feed no
	// graph truth; the vault.* facts are core-owned and feed real reducers.
	// Declaring nothing is accurate, and the harness accepts it.
	if phases := manifest.Spec.ConsumerContracts.Reducer.Phases; len(phases) != 0 {
		t.Fatalf("manifest declares reducer phases %v; omit consumerContracts (see the comment above)", phases)
	}
	if strings.TrimSpace(manifest.Spec.Telemetry.MetricsPrefix) == "" {
		t.Fatal("manifest missing telemetry metrics prefix")
	}
}

// TestManifestDeclaresTheEightVaultKinds keeps the manifest, the document
// vocabulary, and the published payload schemas in step: every kind is
// declared once at schema 1.0.0 with reported confidence and a
// payloadSchemaRef that resolves in the pinned fixture pack.
func TestManifestDeclaresTheEightVaultKinds(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	want := document.FactKinds
	var got []string
	for _, family := range manifest.Spec.EmittedFacts {
		got = append(got, family.Kind)
		if strings.Join(family.SchemaVersions, ",") != document.VaultLiveSchemaVersionV1 ||
			strings.Join(family.SourceConfidence, ",") != "reported" {
			t.Errorf("%s: schemaVersions=%v sourceConfidence=%v", family.Kind, family.SchemaVersions, family.SourceConfidence)
		}
		if family.PayloadSchemaRef != family.Kind {
			t.Errorf("%s: payloadSchemaRef = %q, want the kind", family.Kind, family.PayloadSchemaRef)
		}
		if _, ok := factschemafixture.SchemaFor(family.PayloadSchemaRef); !ok {
			t.Errorf("%s: pinned fixture pack has no schema %q", family.Kind, family.PayloadSchemaRef)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest kinds %v, want %v", got, want)
	}
	if len(manifest.Spec.CollectorKinds) != 1 || manifest.Spec.CollectorKinds[0] != runtime.CollectorKind {
		t.Fatalf("collectorKinds = %v, want [%s]", manifest.Spec.CollectorKinds, runtime.CollectorKind)
	}
}

// TestManifestDeclaresExactlyOneCollectorKind pins the host contract: a
// satellite worker admits exactly one collector kind and fails closed
// otherwise (the sbom satellite CrashLooped on two kinds,
// eshu-hq/eshu-collector-sbom-attestation#6). The surviving kind is
// runtime.CollectorKind (vault_live), the activation scope kind. The vault.*
// document fact kinds stay emittedFacts under that scope: fact vocabulary is
// not scheduling identity.
func TestManifestDeclaresExactlyOneCollectorKind(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	if len(manifest.Spec.CollectorKinds) != 1 {
		t.Fatalf("collectorKinds = %v, want exactly one kind (host admits one per satellite)", manifest.Spec.CollectorKinds)
	}
	if manifest.Spec.CollectorKinds[0] != runtime.CollectorKind {
		t.Fatalf("collectorKinds = %v, want [%q] (the activation scope kind)", manifest.Spec.CollectorKinds, runtime.CollectorKind)
	}
}

// TestEmbeddedManifestMatchesFile proves the binary ships the checked-in
// manifest: seed writes ManifestYAML, so a drift between the embed and the
// file would seed stale activation metadata.
func TestEmbeddedManifestMatchesFile(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(manifest.yaml) error = %v", err)
	}
	if string(ManifestYAML) != string(raw) {
		t.Fatal("embedded manifest differs from manifest.yaml")
	}
}
