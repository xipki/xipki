# Release Checklist (One-Person, Lightweight)

## 1) Pre-merge checks

- [ ] `Quick CI` passed on the PR.
- [ ] `CodeQL` status is green (or findings reviewed and accepted).
- [ ] PR explicitly marked as logic or formatting-only.

## 2) Local verification

- [ ] `mvn -B -ntp -DskipTests compile`
- [ ] `sh tools/check-java-indent.sh`
- [ ] Run impacted unit tests for touched modules.

## 3) Security checks

- [ ] Monthly CVE scan is green, or accepted exceptions are documented.
- [ ] No new high/critical CVEs introduced by dependency changes.
- [ ] Auth and input validation reviewed for changed endpoints.

## 4) Packaging / deploy readiness

- [ ] Build artifact creation command succeeds.
- [ ] Startup smoke test succeeds in a clean environment.
- [ ] Health checks / critical logs look normal.

## 5) Rollback readiness

- [ ] Previous stable artifact/tag is identified.
- [ ] Rollback command/steps are documented and tested once.

## 6) Post-release

- [ ] Monitor logs for auth failures and protocol errors.
- [ ] If issues are found, create follow-up issue with owner/date.
