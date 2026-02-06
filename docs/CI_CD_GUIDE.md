# CI/CD and Security Automation Guide

This guide covers the comprehensive CI/CD pipeline and security automation features built into the ETL Framework.

## 🚀 Overview

The ETL Framework includes enterprise-grade CI/CD workflows that implement security gates, automated testing, and compliance checks. These workflows ensure that every change meets security standards before reaching production.

## 📋 Available Workflows

### 1. **Security Audit Workflow**
**File**: `.github/workflows/security-audit.yml`

**Purpose**: Comprehensive security scanning and vulnerability assessment on every change.

**Key Features**:
- **Bandit SAST**: Static Application Security Testing for Python code
- **Safety Dependency Check**: Vulnerability scanning for Python dependencies
- **Comprehensive Security Audit**: Custom security scoring and analysis
- **SBOM Generation**: Software Bill of Materials for compliance
- **Security Gates**: Automated blocking of insecure code

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests
- Weekly scheduled scans (Monday 6 AM UTC)
- Manual triggers

### 2. **Test Suite Workflow**
**File**: `.github/workflows/test-suite.yml`

**Purpose**: Comprehensive testing across Python versions and test profiles.

**Key Features**:
- **Multi-Python Testing**: Tests on Python 3.9, 3.10, 3.11, 3.12
- **Test Profiles**: Fast, unit, integration, security, functional tests
- **Coverage Reporting**: Code coverage with Codecov integration
- **Parallel Execution**: Faster test runs with parallel jobs

### 3. **Build and Release Workflow**
**File**: `.github/workflows/build-release.yml`

**Purpose**: Automated package building, testing, and publishing.

**Key Features**:
- **Multi-Python Builds**: Build packages for all supported Python versions
- **Release Validation**: Comprehensive tests before release
- **Trusted Publishing**: Secure PyPI publishing without API tokens
- **Security Scan**: Final security check before release
- **Automated Release Notes**: Generated from templates

### 4. **Demo Validation Workflow**
**File**: `.github/workflows/demo-validation.yml`

**Purpose**: Validates all demo scripts work correctly.

**Key Features**:
- **Demo Execution**: Runs all 10 demo scripts
- **Security Output Analysis**: Validates security feature outputs
- **Multi-Python Testing**: Tests demos on Python 3.11 and 3.12
- **Artifact Collection**: Collects demo outputs for inspection

## 🔐 Security Gates Implementation

The CI/CD pipeline implements several security gates that prevent insecure code from reaching production:

### 1. **Code Security Gate**
- **Maximum Bandit Issues**: 10
- **Critical Issues**: Zero tolerance
- **Security Score Minimum**: 70/100

### 2. **Dependency Security Gate**
- **Maximum Vulnerabilities**: 5
- **Critical Vulnerabilities**: Blocks release
- **Outdated Dependencies**: Warning threshold

### 3. **Test Coverage Gate**
- **Minimum Coverage**: 70% (configurable)
- **Security Test Coverage**: Required for all security features
- **Integration Test Coverage**: Required for core functionality

### 4. **Release Security Gate**
- **Final Security Scan**: Required before PyPI publishing
- **SBOM Generation**: Required for compliance
- **Audit Trail**: Complete record of all security checks

## 🛠️ Setup and Configuration

### 1. **Enable GitHub Actions**
The workflows are automatically enabled when you push to the repository. No additional setup is required.

### 2. **Configure Environment Variables**
Set up in repository settings → Secrets and variables → Actions:

**Optional Variables**:
```bash
# For notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

# For PyPI publishing (if not using trusted publishing)
PYPI_API_TOKEN=pypi-xxxxxxxx
```

### 3. **Configure Branch Protection**
Enable in repository settings → Branches → Branch protection rules:

**Required Status Checks**:
```
security-audit / security-gates
test-suite / test
demo-validation / validate-demos
```

**Additional Settings**:
- Require conversation resolution before merging
- Include administrators
- Require approvals

## 🚀 Usage Examples

### Manual Workflow Execution

```bash
# Run security audit
gh workflow run security-audit.yml

# Run specific test profile
gh workflow run test-suite.yml -f test-profile=security

# Create a release
gh workflow run build-release.yml -f version=patch

# Validate specific demo
gh workflow run demo-validation.yml -f demo-number=8
```

### Viewing Results

```bash
# List recent workflow runs
gh run list

# View specific run details
gh run view <run-id>

# Download artifacts
gh run download <run-id> --name=<artifact-name>

# View logs
gh run view <run-id> --log
```

## 📊 Monitoring and Reporting

### 1. **Security Dashboard**
Access via GitHub → Security → Code scanning alerts

**Key Metrics**:
- Security score trend
- Vulnerability count
- Test coverage
- Compliance status

### 2. **Monthly Security Report**
Generate using the security audit script:

```bash
# Run comprehensive audit
python scripts/security_audit.py

# View report
open security_audit_reports/*/COMPREHENSIVE_SECURITY_AUDIT_REPORT.md
```

### 3. **Artifact Storage**
All workflows generate artifacts stored for:
- Security reports: 30 days
- Test results: 7 days
- Build packages: 7 days
- Demo outputs: 7 days

## 🔧 Customization

### 1. **Adjust Security Thresholds**
Edit `.github/workflows/security-audit.yml`:

```yaml
# Adjust these values
- name: Check for critical vulnerabilities
  run: |
    if [ "$VULN_COUNT" -gt 5 ]; then  # Change threshold
      echo "::error::Too many vulnerabilities found ($VULN_COUNT)"
      exit 1
    fi
```

### 2. **Add New Security Scanners**
Extend the security audit workflow:

```yaml
- name: Run Additional Security Scanner
  run: |
    pip install new-security-tool
    new-security-tool --scan src/
```

### 3. **Custom Test Profiles**
Add new test profiles in `.github/workflows/test-suite.yml`:

```yaml
matrix:
  test-profile: ['fast', 'unit', 'integration', 'security', 'functional', 'performance', 'compliance']
```

## 🎯 Best Practices

### 1. **Shift-Left Security**
- Run security scans early in development
- Integrate with pre-commit hooks
- Educate developers on security findings

### 2. **Compliance Automation**
- Generate SBOM for every release
- Maintain audit trail of all security checks
- Document security decisions

### 3. **Continuous Improvement**
- Review security thresholds quarterly
- Update security tools regularly
- Monitor industry security trends

### 4. **Incident Response**
- Document security incident procedures
- Maintain rollback capabilities
- Regular security training

## 🛠️ Troubleshooting

### Common Issues

#### 1. **Security Scan Fails**
**Symptoms**: Workflow fails with security gate violations
**Solutions**:
- Review Bandit findings: `bandit -r src -ll`
- Update vulnerable dependencies
- Fix critical security issues
- Adjust thresholds if appropriate

#### 2. **Tests Fail on Specific Python Version**
**Symptoms**: Tests pass on some Python versions but fail on others
**Solutions**:
- Check version-specific dependencies
- Review test compatibility
- Update Python version matrix
- Add version-specific test skips

#### 3. **Release Fails on PyPI**
**Symptoms**: Build succeeds but PyPI publishing fails
**Solutions**:
- Verify PyPI credentials
- Check package name availability
- Ensure no duplicate releases
- Check network connectivity

#### 4. **Demo Validation Fails**
**Symptoms**: Demos fail in CI but work locally
**Solutions**:
- Check environment variables
- Verify file permissions
- Review demo dependencies
- Check for missing data files

### Debugging Workflows

```bash
# Re-run failed jobs
gh run rerun <run-id> --failed

# Download all artifacts
gh run download <run-id>

# View workflow visualization
gh run view <run-id> --web

# Check workflow status
gh run watch <run-id>
```

## 📚 Related Documentation

- [Security Guide](SECURITY_GUIDE.md) - Framework security features
- [Developer Guide](DEVELOPER_GUIDE.md) - Contribution guidelines
- [Getting Started](GETTING_STARTED.md) - Quick start guide
- [User Guide](USER_GUIDE.md) - Framework usage

## 🎯 Next Steps

1. **Configure Branch Protection**: Enable required status checks
2. **Set Up Notifications**: Configure Slack/Teams alerts
3. **Monitor Metrics**: Track security score trends
4. **Regular Reviews**: Quarterly security review
5. **Continuous Improvement**: Update security thresholds

---

*Last updated: $(date)*
*Maintained by: ETL Framework Security Team*

## 🔗 Useful Links

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Safety Documentation](https://pyup.io/safety/)
- [Codecov Documentation](https://docs.codecov.com/)
- [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)