# Class-Based Testing with pytest-terraform

This document outlines the "Hybrid Workaround Pattern" for using `pytest-terraform` with class-based tests in the Cloud Custodian GCP provider.

## Background

The `pytest-terraform` plugin is designed for function-based tests, but Cloud Custodian's test suite uses class-based tests that inherit from `BaseTest`. This pattern allows us to use terraform fixtures with class-based tests while maintaining compatibility with the existing test infrastructure.

## The Hybrid Workaround Pattern

### Pattern Overview

1. Register a terraform fixture at **module level** (not class level)
2. Use an `autouse` fixture in the test class to inject the terraform fixture
3. Clear the HTTP client cache before each test method to prevent authentication issues
4. Access the terraform fixture via `self.terraform_fixture_name`

### Step-by-Step Implementation

#### Step 1: Register Terraform Fixture at Module Level

```python
from pytest_terraform import terraform

# Register at module level with default scope (module)
@terraform('my_resource')
def _my_resource_fixture():
    """Module-level fixture registration for class-based test workaround."""
    pass
```


#### Step 2: Create Test Class with Setup Fixture

```python
from gcp_common import BaseTest
from c7n_gcp.client import LOCAL_THREAD
import pytest

class TestMyResourceWorkaround(BaseTest):
    """Test my resource using the workaround pattern."""

    @pytest.fixture(autouse=True)
    def setup(self, my_resource):
        """Auto-use fixture to inject terraform fixture and clear HTTP cache.
        
        The HTTP cache clearing is necessary because BaseTest.cleanUp() is not called
        between test methods in pytest's class-based execution. Without this, subsequent
        test methods will reuse the HTTP client from the first test, which may have stale
        credentials, resulting in a 401 Unauthorized error.
        """
        # Clear cached HTTP client before each test to prevent cross-test interference
        # Must DELETE the attribute, not just set to None, because hasattr() checks existence
        if hasattr(LOCAL_THREAD, 'http'):
            delattr(LOCAL_THREAD, 'http')
        
        # Inject the terraform fixture into the class
        self.my_resource = my_resource
```

#### Step 3: Write Test Methods

```python
    def test_my_resource_query(self):
        """Test querying my resource."""
        from c7n_gcp.client import get_default_project
        from c7n.testing import C7N_FUNCTIONAL
        
        # Use record_flight_data in functional mode, replay_flight_data otherwise
        if C7N_FUNCTIONAL:
            project_id = get_default_project()
            session_factory = self.record_flight_data(
                'my-resource-query', project_id=project_id)
        else:
            session_factory = self.replay_flight_data('my-resource-query')

        policy = self.load_policy(
            {'name': 'my-resource-test',
             'resource': 'gcp.my-resource'},
            session_factory=session_factory)

        resources = policy.run()
        
        # Assertions
        assert len(resources) > 0
        
        # Verify terraform fixture is accessible
        if self.my_resource:
            print(f'Terraform fixture available: {self.my_resource}')
```

## Recording and Replaying Tests

### Recording Flight Data (Functional Mode)

To record API responses for later replay:

```bash
# Set C7N_FUNCTIONAL=yes to enable recording mode
C7N_FUNCTIONAL=yes python -m pytest tests/test_myresource.py::TestMyResourceWorkaround -v
```

**What happens:**
1. Terraform creates real infrastructure in GCP
2. Tests run against real GCP APIs
3. API responses are recorded to `tests/data/flights/<test-name>/`
4. Terraform destroys the infrastructure after tests complete

**Flight data location:**
- Recorded files: `tools/c7n_gcp/tests/data/flights/<test-name>/`
- Each API call is saved as a separate JSON file
- File naming: `<method>-<api-path>_<sequence>.json`

### Replaying Tests (Default Mode)

To run tests using recorded data without hitting GCP APIs:

```bash
# Default mode - uses recorded flight data
python -m pytest tests/test_myresource.py::TestMyResourceWorkaround -v

# Or explicitly use --tf-replay flag
python -m pytest tests/test_myresource.py::TestMyResourceWorkaround -v --tf-replay
```

**What happens:**
1. Terraform infrastructure is NOT created (uses replay mode)
2. Tests use recorded API responses from `tests/data/flights/`
3. No real GCP API calls are made
4. Tests run much faster

## Important Considerations


### Multiple Test Methods

Each test method in the class should:
1. Use a unique flight data name for recording
2. Follow the record/replay pattern shown above
3. Not duplicate the HTTP cache clearing (it's in the `setup` fixture)

## Example: Complete Test File

See `tools/c7n_gcp/tests/test_vertexai.py` for a complete working example:
- Module-level fixture: `_vertexai_endpoint_fixture_for_class()`
- Test class: `TestVertexAIEndpointWorkaround`
- Multiple test methods with different flight data recordings
