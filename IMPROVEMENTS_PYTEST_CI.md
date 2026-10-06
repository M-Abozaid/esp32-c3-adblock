# Pytest CI Integration

## Status: Implemented

### GitHub Actions Workflow
- File: `.github/workflows/pytest.yml`
- Triggers: push to main/develop, pull requests to main/develop
- Python versions tested: 3.9, 3.10, 3.11

### Features
- Automatic pytest execution on each push and PR
- Test failure blocks merge (status check)
- Coverage reporting (CodeCov integration)
- Dependency installation from requirements.txt

### Running Tests Locally
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-summary
```

### CI Status Check
- Red X: tests failed, PR cannot merge
- Green checkmark: tests passed, PR ready to review

### Coverage Target
- Target: >70% code coverage
- Reports visible in CodeCov dashboard per PR

### Configuration
- tests/ directory: where test files live (test_*.py or *_test.py)
- requirements.txt: test dependencies
- pytest.ini (optional): additional pytest configuration
