# Contributing to Project Tron

Thank you for your interest in making Tron better. All contributions are welcome —
bug reports, feature requests, code, documentation, or training data.

## Getting started

1. **Fork** the repository and clone your fork
2. **Create a branch** for your change: `git checkout -b feat/my-improvement`
3. **Build** the project: `dotnet build`
4. **Make your changes** — see project structure below
5. **Open a pull request** against `master`

## Project structure

```
src/
  Tron.Core/       Models, interfaces, config — shared by all projects
  Tron.Monitors/   Platform-native collectors + 6 monitor implementations
  Tron.Alerting/   Discord sink + AI analyzer
  Tron.Service/    Worker service host, dashboard, entry point
docs/
  custom-model.md  Design doc for the future fine-tuned security model
build/
  linux/           Linux install scripts
.github/
  workflows/       CI — multi-platform release pipeline
```

## Coding conventions

- **C# 13 / .NET 10** — use modern language features
- Target `net10.0`; do not introduce platform-specific APIs without `#if TRON_WINDOWS` guards
- All new monitors must implement `IMonitor` and be registered in `Program.cs`
- No external HTTP calls during normal operation (no cloud dependencies)
- `appsettings.json` defaults must work with zero configuration (Discord/AI optional)

## Platform support

Tron must remain cross-platform. Any change that adds platform-specific code must:
- Use `OperatingSystem.IsWindows()` / `OperatingSystem.IsLinux()` / `OperatingSystem.IsMacOS()` for runtime branching
- Use `#if TRON_WINDOWS` for compile-time exclusion of Windows-only packages
- Include equivalent logic for Linux/macOS (or gracefully degrade with a log warning)

## Reporting bugs

Open a GitHub Issue with:
- Tron version (from the binary version or git tag)
- Operating system and version
- Relevant log output (from console or `journalctl -u tron`)
- Steps to reproduce

## Feature requests

Open a GitHub Issue describing:
- What you want Tron to detect or do
- Why it matters for security monitoring
- (Optional) how you'd implement it

## Training data contributions

If you want to contribute to the `tron-model` training data (see `docs/custom-model.md`):
- Please open an Issue first to discuss the dataset format
- All contributed data must be public domain, CC0, or your own work
- No personal or proprietary telemetry — synthetic and anonymised data only
