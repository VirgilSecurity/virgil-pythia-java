# Changelog

## Unreleased

### Changed
- Build: upgraded to Gradle 8.7 and moved to a version catalog (`gradle/libs.versions.toml`).
- Tooling: build runs on JDK 17 (library bytecode remains Java 8 compatible).
- Android build: upgraded Android Gradle Plugin, compile/target SDK updated to 34.
- Dependencies: upgraded Virgil dependencies (notably `com.virgilsecurity.sdk:*` to `7.4.0` and `com.virgilsecurity.crypto:*` to `0.17.2`).
- CI: migrated from Travis to GitHub Actions (`.github/workflows/build-and-test.yml`).

### Added
- `.ci/encrypt-env.sh` and `.ci/decrypt-env.sh` for optional secret-gated integration tests via `env.json.enc`.

