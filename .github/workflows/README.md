# GitHub Actions Workflows for ETL Framework

This directory contains comprehensive CI/CD workflows for the ETL Framework, implementing enterprise-grade security gates, testing, and deployment automation.

## 📋 Available Workflows

### 1. **Security Audit** (`security-audit.yml`)
**Purpose**: Comprehensive security scanning and vulnerability assessment

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Weekly schedule (Monday 6 AM UTC)
- Manual trigger

**Jobs**:
- `security-audit`: Runs Bandit SAST, Safety dependency check, and comprehensive security audit
- `sbom-generation`: Generates Software Bill of Materials (SBOM)
- `security-gates`: Evaluates security thresholds and fails if criteria not met
- `notify`: Sends notifications on failure (placeholder for Slack/Teams integration)

**Security Gates**:
- Maximum 10 Bandit issues
- Maximum 5 dependency vulnerabilities
- Minimum security score of 70/100

### 2. **Test Suite** (`test-suite.yml`)
**Purpose**: Comprehensive testing across Python versions and test profiles

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual trigger with test profile selection

**Jobs**:
- `test`: Runs test matrix across Python 3.9-3.12 and test profiles (fast, unit, integration, security, functional)
- `test-coverage`: Generates coverage reports and uploads to Codecov
- `test-summary`: Provides consolidated test results

**Test Profiles**:
- `fast`: Quick tests (excludes slow/performance tests)
- `unit`: Unit tests only
- `integration`: Integration tests
- `security`: Security-focused tests
- `functional`: Business workflow tests
- `all`: All tests (manual trigger only)
- `coverage`: Coverage-focused run

### 3. **Build and Release** (`build-release.yml`)
**Purpose**: Package building, testing, and publishing

**Triggers**:
- Tag push (v* pattern)
- Manual trigger with version selection

**Jobs**:
- `build`: Builds package across Python versions
- `test-release`: Runs release validation tests
- `create-release`: Creates GitHub release with artifacts
- `publish-pypi`: Publishes to PyPI using trusted publishing
- `security-scan-release`: Final security scan before release

**Release Process**:
1. Build package across all supported Python versions
2. Run release validation tests
3. Create GitHub release with release notes
4. Publish to PyPI
5. Final security scan (blocks release if issues found)

### 4. **Demo Validation** (`demo-validation.yml`)
**Purpose**: Validates all demo scripts work correctly

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual trigger with demo selection

**Jobs**:
- `validate-demos`: Runs demo scripts and checks outputs
- `demo-security-check`: Analyzes security outputs from demos
- `demo-summary`: Provides demo validation summary

## 🔐 Security Features in CI/CD

The workflows implement several security best practices:

### 1. **Shift-Left Security**
- Security scanning on every PR
- Prevents merging of vulnerable code
- Early detection of security issues

### 2. **Compliance Requirements**
- SBOM generation for software transparency
- Audit trail of all security scans
- Compliance with security standards

### 3. **Quality Gates**
- Minimum test coverage requirements
- Security score thresholds
- Dependency vulnerability limits

### 4. **Trusted Publishing**
- Uses PyPI's trusted publishing (no API tokens)
- Environment protection for production releases
- Automated release notes generation

## 🚀 Usage Examples

### Manual Security Audit
```bash
# Trigger via GitHub UI or API
gh workflow run security-audit.yml
```

### Run Specific Test Profile
```bash
# Run security tests only
gh workflow run test-suite.yml -f test-profile=security
```

### Create Release
```bash
# Create patch release
gh workflow run build-release.yml -f version=patch
```

### Validate Specific Demo
```bash
# Run demo 08 (RBAC demo)
gh workflow run demo-validation.yml -f demo-number=8
```

## 📊 Monitoring and Notifications

### Artifacts
Each workflow generates artifacts:
- Security reports (JSON, Markdown)
- Test results and coverage reports
- Build packages
- Demo outputs

### Notifications
Configure in `security-audit.yml`:
```yaml
# Add your notification integration
- name: Send Slack notification
  if: failure()
  run: |
    curl -X POST -H 'Content-type: application/json' \
      --data '{"text":"Security audit failed!"}' \
      ${{ secrets.SLACK_WEBHOOK_URL }}
```

## 🔧 Configuration

### Environment Variables
Set in repository settings → Secrets and variables → Actions:

**Required for PyPI Publishing**:
- `PYPI_API_TOKEN` (if not using trusted publishing)

**Optional for Notifications**:
- `SLACK_WEBHOOK_URL`
- `TEAMS_WEBHOOK_URL`
- `EMAIL_SMTP_SERVER`

### Branch Protection Rules
Configure in repository settings → Branches → Branch protection rules:

1. **Require status checks to pass**:
   - `security-audit / security-gates`
   - `test-suite / test`
   - `demo-validation / validate-demos`

2. **Require conversation resolution before merging**

3. **Include administrators**

## 📈 Metrics and Reporting

### Security Dashboard
View security metrics in:
1. **GitHub Security** → Code scanning alerts
2. **Codecov** → Test coverage trends
3. **Workflow runs** → Success/failure rates

### Monthly Security Report
Generate using:
```bash
# Run comprehensive audit
python scripts/security_audit.py

# View report
open security_audit_reports/*/COMPREHENSIVE_SECURITY_AUDIT_REPORT.md
```

## 🛠️ Troubleshooting

### Common Issues

1. **Security scan fails with too many issues**
   - Review Bandit findings: `bandit -r src -ll`
   - Fix critical issues first
   - Update vulnerable dependencies

2. **Tests fail on specific Python version**
   - Check version-specific dependencies
   - Review test compatibility
   - Update Python version matrix

3. **Release fails on PyPI**
   - Check PyPI credentials
   - Verify package name availability
   - Check for duplicate releases

### Debugging Workflows

1. **Download artifacts**:
   ```bash
   gh run download <run-id> --name=<artifact-name>
   ```

2. **Re-run failed jobs**:
   ```bash
   gh run rerun <run-id> --failed
   ```

3. **View workflow logs**:
   ```bash
   gh run view <run-id> --log
   ```

## 📚 Related Documentation

- [ETL Framework Security Guide](../docs/SECURITY_GUIDE.md)
- [Getting Started Guide](../docs/GETTING_STARTED.md)
- [User Guide](../docs/USER_GUIDE.md)
- [Demo Scripts](../demo/)

## 🎯 Next Steps

1. **Configure branch protection rules**
2. **Set up notification integrations**
3. **Monitor workflow success rates**
4. **Review and adjust security thresholds**
5. **Add additional security scanners** (optional)
