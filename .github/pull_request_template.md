## Summary

Describe what changed and why.

## Change Type

- [ ] Logic change
- [ ] Security-relevant change
- [ ] Formatting-only change (no behavior change)

## Risk Scope

- [ ] `gateway` touched
- [ ] `ca-server` touched
- [ ] `security` touched
- [ ] None of the above

## Validation

- [ ] `mvn -B -ntp -DskipTests compile`
- [ ] `sh tools/check-java-indent.sh`
- [ ] Relevant tests added/updated

## Security Checklist

- [ ] Inputs validated for new/changed endpoints
- [ ] AuthZ/AuthN impact reviewed
- [ ] Error handling does not leak sensitive data
- [ ] Dependencies reviewed for new CVEs

## Rollback

Describe how to rollback if needed.
