"""Tests for FQL injection prevention and input sanitization.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    Falcon Digest
`-------'                         `-------'

Falcon Digest — AI-Powered Falcon Security Dashboard

Copyright 2024 CrowdStrike, Inc.

MIT License — see LICENSE file for details.
"""

import pytest
import json
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestFQLInjectionViaTools:
    """Verify that tool handlers cope with malicious FQL input."""

    @pytest.mark.asyncio
    async def test_alerts_product_injection(self):
        """Malicious product value does not crash search_alerts."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_alerts
            # Single-quote injection attempt
            result = await search_alerts(
                product="cao'+severity:'Critical", hours=24, limit=10
            )
            # Should still return parseable JSON or an error string
            try:
                data = json.loads(result)
                assert isinstance(data, dict)
            except json.JSONDecodeError:
                # An error string is also acceptable
                assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_host_hostname_injection(self):
        """Malicious hostname does not crash get_host_details."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import get_host_details
            result = await get_host_details(
                hostname="test'+OR+1:1+OR+hostname:'"
            )
            # Should return a string (not found message or error)
            assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_fql_filter_injection(self):
        """FQL validation tool handles injected filter strings."""
        from crwd_mcp_server import test_fql_filter
        # Injected filter with unbalanced quotes
        result = await test_fql_filter("product:'cao'+severity:'Critical")
        data = json.loads(result)
        assert data["valid"] is False
        assert any("Unbalanced" in issue for issue in data["issues"])

    @pytest.mark.asyncio
    async def test_cases_status_injection(self):
        """Malicious status value does not crash search_cases."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(
                status="open'+severity:>=0+status:'", hours=72, limit=10
            )
            try:
                data = json.loads(result)
                assert isinstance(data, dict)
            except json.JSONDecodeError:
                assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_vulns_severity_injection(self):
        """Malicious severity value does not crash search_vulnerabilities."""
        mock_client = MagicMock()
        mock_client.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_vulnerabilities
            result = await search_vulnerabilities(
                severity="CRITICAL'+status:'open", limit=10
            )
            try:
                data = json.loads(result)
                assert isinstance(data, dict)
            except json.JSONDecodeError:
                assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_threatgraph_indicator_injection(self):
        """Malicious indicator value does not crash search_threatgraph."""
        mock_client = MagicMock()
        mock_client.combined_ran_on_get.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph(
                indicator_type="domain",
                indicator_value="evil.com'+OR+1:1",
                limit=5
            )
            data = json.loads(result)
            assert isinstance(data, dict)


class TestSanitizeFQLValueStub:
    """Tests for the sanitize_fql_value helper.

    These tests document the expected sanitization contract.  If the
    function does not yet exist the tests are skipped automatically.
    """

    @pytest.fixture(autouse=True)
    def _import_sanitize(self):
        """Try to import sanitize_fql_value; skip if it does not exist."""
        try:
            from crwd_mcp_server import sanitize_fql_value
            self.sanitize_fql_value = sanitize_fql_value
        except ImportError:
            pytest.skip("sanitize_fql_value not yet implemented")

    def test_single_quote_injection(self):
        """Single quotes are stripped or escaped."""
        result = self.sanitize_fql_value("cao'+severity:'Critical")
        assert "'" not in result

    def test_backslash_injection(self):
        """Backslashes are stripped or escaped."""
        result = self.sanitize_fql_value("cao\\")
        assert "\\" not in result

    def test_hostname_injection(self):
        """Complex injection payloads are neutralized."""
        malicious = "test'+OR+1:1+OR+hostname:'"
        cleaned = self.sanitize_fql_value(malicious)
        assert "'" not in cleaned

    def test_safe_values_pass_through(self):
        """Normal values are not corrupted by sanitization."""
        assert self.sanitize_fql_value("cao") == "cao"
        assert self.sanitize_fql_value("Critical") == "Critical"
        assert self.sanitize_fql_value("test-host.example.com") == "test-host.example.com"
        assert self.sanitize_fql_value("192.168.1.1") == "192.168.1.1"
        assert self.sanitize_fql_value("user@example.com") == "user@example.com"
