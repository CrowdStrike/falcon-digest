"""Shared test fixtures for CrowdStrike MCP tests."""

import pytest
import json
import os
from unittest.mock import MagicMock, patch, AsyncMock


@pytest.fixture
def mock_env_vars():
    """Set test environment variables."""
    env = {
        "FALCON_CLIENT_ID": "test-client-id",
        "FALCON_CLIENT_SECRET": "test-client-secret",
        "FALCON_BASE_URL": "https://api.test.crowdstrike.com",
        "LLM_ENDPOINT": "https://llm.test.example.com",
        "LLM_API_KEY": "test-api-key",
    }
    with patch.dict(os.environ, env):
        yield env


@pytest.fixture
def mock_alerts_response():
    """Mock Alerts API response."""
    return {
        "status_code": 200,
        "body": {
            "resources": ["alert-id-1", "alert-id-2"],
            "meta": {"pagination": {"total": 2}}
        }
    }


@pytest.fixture
def mock_alert_details():
    """Mock alert detail objects."""
    return {
        "status_code": 200,
        "body": {
            "resources": [
                {
                    "composite_id": "alert-id-1",
                    "severity_name": "Critical",
                    "product": "cao",
                    "external_provider_name": "TestProvider",
                    "tactic": "InitialAccess",
                    "technique": "Phishing",
                    "status": "new",
                    "created_timestamp": "2026-03-04T00:00:00Z",
                    "description": "Test alert description"
                }
            ]
        }
    }


@pytest.fixture
def mock_cases_response():
    """Mock Cases API response."""
    return {
        "status_code": 200,
        "body": {
            "resources": ["case-id-1"],
            "meta": {"pagination": {"total": 1}}
        }
    }


@pytest.fixture
def mock_case_details():
    """Mock case detail objects."""
    return {
        "status_code": 200,
        "body": {
            "resources": [
                {
                    "id": "case-id-1",
                    "title": "Test Case",
                    "description": "Test case description",
                    "status": "open",
                    "severity": 80,
                    "tags": ["test"],
                    "created_time": "2026-03-04T00:00:00Z",
                    "assigned_to_name": "Tester"
                }
            ]
        }
    }


@pytest.fixture
def mock_hosts_response():
    """Mock Hosts API response."""
    return {
        "status_code": 200,
        "body": {
            "resources": ["device-id-1"]
        }
    }


@pytest.fixture
def mock_host_details():
    """Mock host detail objects."""
    return {
        "status_code": 200,
        "body": {
            "resources": [
                {
                    "device_id": "device-id-1",
                    "hostname": "test-host",
                    "platform_name": "Windows",
                    "os_version": "10.0",
                    "status": "normal",
                    "last_seen": "2026-03-04T00:00:00Z",
                    "local_ip": "10.0.0.1",
                    "external_ip": "1.2.3.4",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "agent_version": "7.0",
                    "tags": ["test"]
                }
            ]
        }
    }


@pytest.fixture
def mock_vuln_response():
    """Mock Spotlight Vulnerabilities API response."""
    return {
        "status_code": 200,
        "body": {
            "resources": ["vuln-id-1"],
            "meta": {"pagination": {"total": 1}}
        }
    }


@pytest.fixture
def mock_vuln_details():
    """Mock vulnerability detail objects."""
    return {
        "status_code": 200,
        "body": {
            "resources": [
                {
                    "id": "vuln-id-1",
                    "cve": {
                        "id": "CVE-2026-0001",
                        "severity": "CRITICAL",
                        "base_score": 9.8,
                        "description": "Test vulnerability",
                        "exploitability_score": 3.9
                    },
                    "host_info": {
                        "hostname": "test-host",
                        "os_version": "10.0"
                    },
                    "status": "open",
                    "created_timestamp": "2026-03-04T00:00:00Z",
                    "app": {"product_name_version": "TestApp 1.0"}
                }
            ]
        }
    }


@pytest.fixture
def mock_falcon_client():
    """Create a mock Falcon client that returns configurable responses."""
    client = MagicMock()
    return client
