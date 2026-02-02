# Release and Supply-Chain Plan (minimal)

waxseal handles sensitive workflows. Releases must be easy to verify.

- Build GitHub Release binaries for `windows`, `darwin`, `linux` (amd64/arm64).
- Publish `checksums.txt` for every release.
- Prefer adding an SBOM (SPDX or CycloneDX) once the build is stable.

Non-goal for v1:

- Cosign signing / provenance. Start with checksums + SBOM; add signing once the release pipeline is stable.
