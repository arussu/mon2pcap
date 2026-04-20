# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

- `Added` - for new features.
- `Changed` - for changes in existing functionality.
- `Deprecated` - for soon-to-be removed features.
- `Removed` - for now removed features.
- `Fixed` - for any bug fixes.
- `Security` - in case of vulnerabilities.

## [1.0.8] - 2026-04-18:
### Fixed
- `Diameter._extract_diameter_length()` failed to parse `Message Length: N(0xHH)` verbose format — the decimal value before the parenthesis is now used instead of the hex value inside it
- `TypeError: 'ABCMeta' object is not subscriptable` on Python 3.8
### Changed
- Migrated build system from Poetry to uv; `pyproject.toml` updated to PEP 621 standard (`[project]`, `[dependency-groups]`, `hatchling` backend)
- Minimum Python version set to 3.8 (was 3.6; dev dependencies already required ≥3.8)

## [1.0.7] - 2023-06-05:
### Changed
- Type hinting fix

## [1.0.6] - 2023-06-05:
### Added
- Ignore empty lines 

## [1.0.5] - 2023-06-05:
### Added
- LMISF protocol support 

## [1.0.4] - 2023-06-05:
### Fixed
- import fix 

## [1.0.3] - 2023-06-04:
### Changed
- There is no reason to not support earlier python versions.  
  Python dependency lowered to 3.8.1

## [1.0.2] - 2023-06-04:
### Added
- single source of truth for version variable
### Fixed
- import fix (typo)

## [1.0.0] - 2023-06-01:
### Added
- initial release

[1.0.0]: https://github.com/arussu/mon2pcap/releases/tag/v1.0.0
[1.0.2]: https://github.com/arussu/mon2pcap/compare/v1.0.0...v1.0.2
[1.0.3]: https://github.com/arussu/mon2pcap/compare/v1.0.2...v1.0.3
[1.0.4]: https://github.com/arussu/mon2pcap/compare/v1.0.3...v1.0.4
[1.0.5]: https://github.com/arussu/mon2pcap/compare/v1.0.4...v1.0.5
[1.0.6]: https://github.com/arussu/mon2pcap/compare/v1.0.5...v1.0.6
[1.0.7]: https://github.com/arussu/mon2pcap/compare/v1.0.6...v1.0.7
[1.0.8]: https://github.com/arussu/mon2pcap/compare/v1.0.7...v1.0.8