"""Unit tests for all 10 CrowdStrike MCP server tools."""

import pytest
import json
import sys
import os
from unittest.mock import patch, MagicMock

# Ensure the project root is on sys.path so crwd_mcp_server can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# 1. search_alerts
# ---------------------------------------------------------------------------

class TestSearchAlerts:
    """Tests for the search_alerts tool."""

    @pytest.mark.asyncio
    async def test_search_alerts_basic(self, mock_alerts_response, mock_alert_details):
        """Basic alert search returns valid JSON with expected fields."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = mock_alerts_response
        mock_client.get_alerts.return_value = mock_alert_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_alerts
            result = await search_alerts(product="cao", hours=24, limit=10)
            data = json.loads(result)
            assert data["total_found"] >= 1
            assert len(data["alerts"]) >= 1
            assert data["alerts"][0]["severity"] == "Critical"
            assert data["alerts"][0]["product"] == "cao"
            assert "query_filter" in data

    @pytest.mark.asyncio
    async def test_search_alerts_with_severity_filter(self, mock_alerts_response, mock_alert_details):
        """Alert search with severity filter includes the severity in the FQL."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = mock_alerts_response
        mock_client.get_alerts.return_value = mock_alert_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_alerts
            result = await search_alerts(product="cao", severity="Critical", hours=24, limit=10)
            data = json.loads(result)
            assert data["total_found"] >= 1
            # Verify the filter string includes severity
            assert "severity_name:'Critical'" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_alerts_no_results(self):
        """Alert search with no matching alerts returns empty list."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_alerts
            result = await search_alerts(product="cao", hours=24, limit=10)
            data = json.loads(result)
            assert data["total_found"] == 0
            assert data["alerts"] == []

    @pytest.mark.asyncio
    async def test_search_alerts_api_error(self):
        """Alert search returns error message on API failure."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_alerts
            result = await search_alerts(product="cao", hours=24, limit=10)
            assert "Error" in result or "error" in result.lower()

    @pytest.mark.asyncio
    async def test_search_alerts_exception_handling(self):
        """Alert search handles unexpected exceptions gracefully."""
        with patch("crwd_mcp_server.get_falcon_client", side_effect=Exception("Connection refused")):
            from crwd_mcp_server import search_alerts
            result = await search_alerts(product="cao", hours=24, limit=10)
            assert "Connection refused" in result
            # Server returns structured JSON error
            data = json.loads(result)
            assert "error" in data
            assert "Connection refused" in data["error"]


# ---------------------------------------------------------------------------
# 2. get_host_details
# ---------------------------------------------------------------------------

class TestGetHostDetails:
    """Tests for the get_host_details tool."""

    @pytest.mark.asyncio
    async def test_host_found(self, mock_hosts_response, mock_host_details):
        """Host lookup returns valid JSON with expected device fields."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = mock_hosts_response
        mock_client.get_device_details.return_value = mock_host_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import get_host_details
            result = await get_host_details(hostname="test-host")
            data = json.loads(result)
            assert data["hostname"] == "test-host"
            assert data["platform"] == "Windows"
            assert data["agent_id"] == "device-id-1"
            assert data["local_ip"] == "10.0.0.1"
            assert data["external_ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_host_not_found(self):
        """Host lookup returns descriptive message when host is missing."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import get_host_details
            result = await get_host_details(hostname="nonexistent-host")
            assert "not found" in result.lower() or "error" in result.lower()

    @pytest.mark.asyncio
    async def test_host_api_error(self):
        """Host lookup returns error message on API failure."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal server error"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import get_host_details
            result = await get_host_details(hostname="test-host")
            assert "Error" in result or "error" in result.lower()

    @pytest.mark.asyncio
    async def test_host_exception_handling(self):
        """Host lookup handles unexpected exceptions gracefully."""
        with patch("crwd_mcp_server.get_falcon_client", side_effect=Exception("Timeout")):
            from crwd_mcp_server import get_host_details
            result = await get_host_details(hostname="test-host")
            assert "Timeout" in result
            # Server returns structured JSON error
            data = json.loads(result)
            assert "error" in data
            assert "Timeout" in data["error"]


# ---------------------------------------------------------------------------
# 3. test_fql_filter
# ---------------------------------------------------------------------------

class TestFQLFilter:
    """Tests for the test_fql_filter tool."""

    @pytest.mark.asyncio
    async def test_valid_fql(self):
        """Valid FQL filter is accepted."""
        from crwd_mcp_server import test_fql_filter
        result = await test_fql_filter("product:'cao'+severity_name:'Critical'")
        data = json.loads(result)
        assert data["valid"] is True
        assert data["issues"] is None
        assert "product" in data["detected_fields"]
        assert "severity_name" in data["detected_fields"]

    @pytest.mark.asyncio
    async def test_invalid_fql_unbalanced_quotes(self):
        """Unbalanced single quotes are detected."""
        from crwd_mcp_server import test_fql_filter
        result = await test_fql_filter("product:'cao")
        data = json.loads(result)
        assert data["valid"] is False
        assert any("Unbalanced" in issue for issue in data["issues"])

    @pytest.mark.asyncio
    async def test_invalid_fql_unbalanced_double_quotes(self):
        """Unbalanced double quotes are detected."""
        from crwd_mcp_server import test_fql_filter
        result = await test_fql_filter('product:"cao')
        data = json.loads(result)
        assert data["valid"] is False
        assert any("Unbalanced" in issue for issue in data["issues"])

    @pytest.mark.asyncio
    async def test_empty_fql(self):
        """Empty filter string returns error."""
        from crwd_mcp_server import test_fql_filter
        result = await test_fql_filter("")
        assert "Error" in result or "Empty" in result

    @pytest.mark.asyncio
    async def test_fql_detected_fields(self):
        """Common FQL fields are correctly detected."""
        from crwd_mcp_server import test_fql_filter
        result = await test_fql_filter("product:'epp'+status:'new'+hostname:'test'")
        data = json.loads(result)
        assert "product" in data["detected_fields"]
        assert "status" in data["detected_fields"]
        assert "hostname" in data["detected_fields"]


# ---------------------------------------------------------------------------
# 4. list_available_products
# ---------------------------------------------------------------------------

class TestListAvailableProducts:
    """Tests for the list_available_products tool."""

    @pytest.mark.asyncio
    async def test_returns_all_products(self):
        """All known product types are returned."""
        from crwd_mcp_server import list_available_products
        result = await list_available_products()
        data = json.loads(result)
        assert "available_products" in data
        product_values = [p["value"] for p in data["available_products"]]
        assert "cao" in product_values
        assert "epp" in product_values
        assert "idp" in product_values
        assert "3rdparty" in product_values

    @pytest.mark.asyncio
    async def test_products_have_required_fields(self):
        """Each product entry has value, name, and description."""
        from crwd_mcp_server import list_available_products
        result = await list_available_products()
        data = json.loads(result)
        for product in data["available_products"]:
            assert "value" in product
            assert "name" in product
            assert "description" in product

    @pytest.mark.asyncio
    async def test_example_filters_present(self):
        """Example FQL filters are included in the response."""
        from crwd_mcp_server import list_available_products
        result = await list_available_products()
        data = json.loads(result)
        assert "example_filters" in data
        assert len(data["example_filters"]) > 0


# ---------------------------------------------------------------------------
# 5. search_cases
# ---------------------------------------------------------------------------

class TestSearchCases:
    """Tests for the search_cases tool."""

    @pytest.mark.asyncio
    async def test_search_cases_basic(self, mock_cases_response, mock_case_details):
        """Basic case search returns valid JSON."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = mock_cases_response
        mock_client.get_cases.return_value = mock_case_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(hours=72, limit=10)
            data = json.loads(result)
            assert data["total_found"] >= 1
            assert len(data["cases"]) >= 1
            assert data["cases"][0]["status"] == "open"

    @pytest.mark.asyncio
    async def test_search_cases_critical_severity(self, mock_cases_response, mock_case_details):
        """Critical severity maps to severity>=75 in FQL."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = mock_cases_response
        mock_client.get_cases.return_value = mock_case_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(severity="critical", hours=72, limit=10)
            data = json.loads(result)
            # Verify the filter includes severity>=75
            assert "severity:>=75" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_cases_with_status(self, mock_cases_response, mock_case_details):
        """Status filter is included in FQL."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = mock_cases_response
        mock_client.get_cases.return_value = mock_case_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(status="open", hours=72, limit=10)
            data = json.loads(result)
            assert "status:'open'" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_cases_no_results(self):
        """Empty case search returns zero results."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(hours=72, limit=10)
            data = json.loads(result)
            assert data["total_found"] == 0
            assert data["cases"] == []

    @pytest.mark.asyncio
    async def test_search_cases_api_error(self):
        """Case search returns error JSON on API failure."""
        mock_client = MagicMock()
        mock_client.query_case_ids.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_cases
            result = await search_cases(hours=72, limit=10)
            data = json.loads(result)
            assert "error" in data


# ---------------------------------------------------------------------------
# 6. search_detections
# ---------------------------------------------------------------------------

class TestSearchDetections:
    """Tests for the search_detections tool."""

    @pytest.mark.asyncio
    async def test_search_detections_basic(self, mock_alerts_response, mock_alert_details):
        """Basic detection search returns valid JSON with product:epp in filter."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = mock_alerts_response
        mock_client.get_alerts.return_value = mock_alert_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_detections
            result = await search_detections(hours=24, limit=10)
            data = json.loads(result)
            assert "total_found" in data
            assert "detections" in data
            assert "product:'epp'" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_detections_with_severity(self, mock_alerts_response, mock_alert_details):
        """Detection search with severity includes it in FQL."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = mock_alerts_response
        mock_client.get_alerts.return_value = mock_alert_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_detections
            result = await search_detections(severity="Critical", hours=24, limit=10)
            data = json.loads(result)
            assert "severity_name:'Critical'" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_detections_no_results(self):
        """Detection search with no matches returns empty list."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_detections
            result = await search_detections(hours=24, limit=10)
            data = json.loads(result)
            assert data["total_found"] == 0
            assert data["detections"] == []

    @pytest.mark.asyncio
    async def test_search_detections_api_error(self):
        """Detection search returns error JSON on API failure."""
        mock_client = MagicMock()
        mock_client.query_alerts.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Server error"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_detections
            result = await search_detections(hours=24, limit=10)
            data = json.loads(result)
            assert "error" in data


# ---------------------------------------------------------------------------
# 7. search_vulnerabilities
# ---------------------------------------------------------------------------

class TestSearchVulnerabilities:
    """Tests for the search_vulnerabilities tool."""

    @pytest.mark.asyncio
    async def test_search_vulns_basic(self, mock_vuln_response, mock_vuln_details):
        """Basic vulnerability search returns valid JSON."""
        mock_client = MagicMock()
        mock_client.query_vulnerabilities.return_value = mock_vuln_response
        mock_client.get_vulnerabilities.return_value = mock_vuln_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_vulnerabilities
            result = await search_vulnerabilities(severity="critical", limit=10)
            data = json.loads(result)
            assert data["total_found"] >= 1
            assert len(data["vulnerabilities"]) >= 1
            vuln = data["vulnerabilities"][0]
            assert vuln["cve_id"] == "CVE-2026-0001"
            assert vuln["severity"] == "CRITICAL"
            assert vuln["base_score"] == 9.8

    @pytest.mark.asyncio
    async def test_search_vulns_severity_filter(self, mock_vuln_response, mock_vuln_details):
        """Vulnerability severity filter is uppercased in FQL."""
        mock_client = MagicMock()
        mock_client.query_vulnerabilities.return_value = mock_vuln_response
        mock_client.get_vulnerabilities.return_value = mock_vuln_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_vulnerabilities
            result = await search_vulnerabilities(severity="critical", limit=10)
            data = json.loads(result)
            assert "cve.severity:'CRITICAL'" in data["query_filter"]

    @pytest.mark.asyncio
    async def test_search_vulns_no_results(self):
        """Empty vulnerability search returns zero results."""
        mock_client = MagicMock()
        mock_client.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_vulnerabilities
            result = await search_vulnerabilities(limit=10)
            data = json.loads(result)
            assert data["total_found"] == 0
            assert data["vulnerabilities"] == []

    @pytest.mark.asyncio
    async def test_search_vulns_api_error(self):
        """Vulnerability search returns error JSON on API failure."""
        mock_client = MagicMock()
        mock_client.query_vulnerabilities.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_vulnerabilities
            result = await search_vulnerabilities(limit=10)
            data = json.loads(result)
            assert "error" in data


# ---------------------------------------------------------------------------
# 8. search_threatgraph
# ---------------------------------------------------------------------------

class TestSearchThreatGraph:
    """Tests for the search_threatgraph tool."""

    @pytest.mark.asyncio
    async def test_ioc_lookup(self):
        """IOC lookup mode returns devices list."""
        mock_client = MagicMock()
        mock_client.combined_ran_on_get.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "device_id": "dev-1",
                        "object_id": "obj-1",
                        "edge_type": "communicates_with",
                        "direction": "outbound",
                        "scope": "device",
                        "timestamp": "2026-03-04T00:00:00Z"
                    }
                ]
            }
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph(
                indicator_type="domain", indicator_value="evil.com", limit=5
            )
            data = json.loads(result)
            assert data["query_type"] == "ioc_lookup"
            assert data["indicator_type"] == "domain"
            assert data["indicator_value"] == "evil.com"
            assert data["total_found"] >= 1
            assert data["devices"][0]["device_id"] == "dev-1"

    @pytest.mark.asyncio
    async def test_vertex_summary(self):
        """Vertex summary mode returns vertex details."""
        mock_client = MagicMock()
        mock_client.combined_summary_get.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "vtx-1",
                        "vertex_type": "device",
                        "scope": "device",
                        "timestamp": "2026-03-04T00:00:00Z",
                        "properties": {"hostname": "test-host"}
                    }
                ]
            }
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph(
                vertex_type="device", vertex_id="vtx-1", scope="device", limit=5
            )
            data = json.loads(result)
            assert data["query_type"] == "vertex_summary"
            assert data["vertex_type"] == "device"
            assert data["total_found"] >= 1
            assert data["vertices"][0]["id"] == "vtx-1"

    @pytest.mark.asyncio
    async def test_edge_types_listing(self):
        """No-args call returns edge type listing."""
        mock_client = MagicMock()
        mock_client.get_edge_types.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["communicates_with", "ran_on", "loaded_by"]
            }
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph()
            data = json.loads(result)
            assert data["query_type"] == "edge_types"
            assert data["total_edge_types"] == 3
            assert "communicates_with" in data["edge_types"]
            assert "usage_hint" in data

    @pytest.mark.asyncio
    async def test_threatgraph_ioc_api_error(self):
        """IOC lookup returns error JSON on API failure."""
        mock_client = MagicMock()
        mock_client.combined_ran_on_get.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph(
                indicator_type="domain", indicator_value="evil.com"
            )
            data = json.loads(result)
            assert "error" in data

    @pytest.mark.asyncio
    async def test_threatgraph_exception_handling(self):
        """ThreatGraph handles exceptions gracefully."""
        with patch("crwd_mcp_server.get_falcon_client", side_effect=Exception("Network error")):
            from crwd_mcp_server import search_threatgraph
            result = await search_threatgraph(
                indicator_type="domain", indicator_value="evil.com"
            )
            data = json.loads(result)
            assert "error" in data
            assert "Network error" in data["error"]


# ---------------------------------------------------------------------------
# 9. get_security_posture
# ---------------------------------------------------------------------------

class TestGetSecurityPosture:
    """Tests for the get_security_posture tool."""

    def _hosts_mock(self):
        """Create a Hosts mock with all the queries get_security_posture makes."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }
        return mock_client

    def _alerts_mock(self, severity_counts=None):
        """Create an Alerts mock. severity_counts: dict of severity->total."""
        severity_counts = severity_counts or {}
        mock_client = MagicMock()

        def mock_query_alerts(**kwargs):
            fql = kwargs.get("filter", "")
            for sev, count in severity_counts.items():
                if sev in fql:
                    return {
                        "status_code": 200,
                        "body": {"resources": ["a1"] if count else [], "meta": {"pagination": {"total": count}}}
                    }
            return {
                "status_code": 200,
                "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
            }

        mock_client.query_alerts.side_effect = mock_query_alerts
        # get_alerts for top tactics
        mock_client.get_alerts.return_value = {
            "status_code": 200,
            "body": {"resources": []}
        }
        return mock_client

    @pytest.mark.asyncio
    async def test_security_posture_basic(self):
        """Security posture returns expected structure."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                return self._hosts_mock()
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert "risk_score" in data
            assert "risk_level" in data
            assert "alerts" in data
            assert "cases" in data
            assert "detections" in data
            assert "vulnerabilities" in data
            assert "hosts" in data
            assert "generated_at" in data
            assert "lookback_hours" in data
            assert data["lookback_hours"] == 24
            # New fields
            assert "stale_count" in data["hosts"]
            assert "contained_count" in data["hosts"]
            assert "by_tactic" in data["alerts"]

    @pytest.mark.asyncio
    async def test_security_posture_risk_score_calculation(self):
        """Risk score is correctly calculated from critical and high counts."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                mock_client = MagicMock()

                def mock_query_alerts(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "product:'epp'" in fql:
                        return {
                            "status_code": 200,
                            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                        }
                    if "Critical" in fql:
                        return {
                            "status_code": 200,
                            "body": {"resources": ["a1"], "meta": {"pagination": {"total": 3}}}
                        }
                    elif "High" in fql:
                        return {
                            "status_code": 200,
                            "body": {"resources": ["a2"], "meta": {"pagination": {"total": 2}}}
                        }
                    return {
                        "status_code": 200,
                        "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                    }
                mock_client.query_alerts.side_effect = mock_query_alerts
                mock_client.get_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": []}
                }
                return mock_client
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                return self._hosts_mock()
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            # Verify alerts were counted correctly
            assert data["alerts"]["by_severity"]["Critical"] == 3
            assert data["alerts"]["by_severity"]["High"] == 2
            # Verify risk score is positive and risk level is assigned
            assert data["risk_score"] > 0
            assert data["risk_level"] in ("Critical", "High", "Medium", "Low")

    @pytest.mark.asyncio
    async def test_security_posture_risk_level_critical(self):
        """Risk score >= 75 yields Critical risk level."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                mock_client = MagicMock()

                def mock_query_alerts(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "product:'epp'" in fql:
                        if "Critical" in fql:
                            return {
                                "status_code": 200,
                                "body": {"resources": [], "meta": {"pagination": {"total": 5}}}
                            }
                        return {
                            "status_code": 200,
                            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                        }
                    if "Critical" in fql:
                        return {
                            "status_code": 200,
                            "body": {"resources": [], "meta": {"pagination": {"total": 5}}}
                        }
                    return {
                        "status_code": 200,
                        "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                    }
                mock_client.query_alerts.side_effect = mock_query_alerts
                mock_client.get_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": []}
                }
                return mock_client
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                return self._hosts_mock()
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            # 5 critical alerts + 5 critical detections = 10 total critical items
            assert data["risk_score"] >= 75
            assert data["risk_level"] == "Critical"

    @pytest.mark.asyncio
    async def test_security_posture_handles_api_errors(self):
        """Security posture handles individual API failures gracefully."""
        def make_mock_client(service_class):
            mock_client = MagicMock()
            # All calls raise
            mock_client.query_alerts.side_effect = Exception("Alert API down")
            mock_client.get_alerts.side_effect = Exception("Alert API down")
            mock_client.query_case_ids.side_effect = Exception("Cases API down")
            mock_client.query_vulnerabilities.side_effect = Exception("Vuln API down")
            mock_client.query_devices_by_filter.side_effect = Exception("Hosts API down")
            return mock_client

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            # Should still return valid JSON with error fields populated
            assert "risk_score" in data
            assert data["risk_score"] == 0

    @pytest.mark.asyncio
    async def test_security_posture_risk_score_capped_at_100(self):
        """Risk score is capped at 100 even with many critical findings."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                mock_client = MagicMock()

                def mock_query_alerts(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "Critical" in fql:
                        return {
                            "status_code": 200,
                            "body": {"resources": [], "meta": {"pagination": {"total": 50}}}
                        }
                    return {
                        "status_code": 200,
                        "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                    }
                mock_client.query_alerts.side_effect = mock_query_alerts
                mock_client.get_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": []}
                }
                return mock_client
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                return self._hosts_mock()
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            # With many critical findings the score approaches but may not
            # equal 100 depending on the sigmoid scaling formula.  The key
            # invariant is that the score never exceeds 100.
            assert data["risk_score"] <= 100
            assert data["risk_score"] >= 90  # Very high with 50+ criticals
            assert data["risk_level"] == "Critical"

    @pytest.mark.asyncio
    async def test_security_posture_includes_stale_and_contained_hosts(self):
        """Security posture includes stale and contained host counts."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                mock_client = MagicMock()
                def mock_query(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "last_seen" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 12}}}}
                    elif "contained" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 3}}}}
                    elif "platform_name" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 100}}}}
                    return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 500}}}}
                mock_client.query_devices_by_filter.side_effect = mock_query
                return mock_client
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["hosts"]["total"] == 500
            assert data["hosts"]["stale_count"] == 12
            assert data["hosts"]["contained_count"] == 3

    @pytest.mark.asyncio
    async def test_security_posture_includes_top_tactics(self):
        """Security posture includes top attack tactics from alerts."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                mock_client = MagicMock()
                mock_client.query_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": ["a1", "a2", "a3"], "meta": {"pagination": {"total": 3}}}
                }
                mock_client.get_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": [
                        {"tactic": "InitialAccess"},
                        {"tactic": "Execution"},
                        {"tactic": "InitialAccess"},
                    ]}
                }
                return mock_client
            elif name == 'CaseManagement':
                mock_client = MagicMock()
                mock_client.query_case_ids.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'SpotlightVulnerabilities':
                mock_client = MagicMock()
                mock_client.query_vulnerabilities.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                return mock_client
            elif name == 'Hosts':
                return self._hosts_mock()
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert "InitialAccess" in data["alerts"]["by_tactic"]
            assert data["alerts"]["by_tactic"]["InitialAccess"] == 2
            assert data["alerts"]["by_tactic"]["Execution"] == 1

    @pytest.mark.asyncio
    async def test_posture_crowdscore(self):
        """CrowdScore section populates current score and 7d trend."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Incidents':
                mock_client = MagicMock()
                mock_client.crowdscore.return_value = {
                    "status_code": 200,
                    "body": {"resources": [
                        {"timestamp": "2025-01-01T12:00:00Z", "score": 42},
                        {"timestamp": "2025-01-01T11:00:00Z", "score": 38},
                    ]}
                }
                mock_client.query_incidents.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
                }
                mock_client.get_incidents.return_value = {
                    "status_code": 200,
                    "body": {"resources": []}
                }
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'ExposureManagement':
                m = MagicMock()
                m.blob_query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["crowdscore"]["current"] == 42
            assert len(data["crowdscore"]["trend_7d"]) == 2
            assert data["crowdscore"]["trend_7d"][0]["score"] == 42
            # CrowdScore should override risk_score
            assert data["risk_score"] == 42
            assert data["risk_level"] == "Medium"

    @pytest.mark.asyncio
    async def test_posture_mttd_mttr(self):
        """MTTD/MTTR computed from alert timing fields."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                mock_client = MagicMock()
                def mock_query_alerts(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "closed" in fql:
                        return {"status_code": 200, "body": {"resources": ["a1", "a2"], "meta": {"pagination": {"total": 2}}}}
                    return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                mock_client.query_alerts.side_effect = mock_query_alerts
                mock_client.get_alerts.return_value = {
                    "status_code": 200,
                    "body": {"resources": [
                        {"seconds_to_triaged": 3600, "seconds_to_resolved": 7200},
                        {"seconds_to_triaged": 1800, "seconds_to_resolved": 5400},
                    ]}
                }
                return mock_client
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Incidents':
                m = MagicMock()
                m.crowdscore.return_value = {"status_code": 200, "body": {"resources": []}}
                m.query_incidents.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'ExposureManagement':
                m = MagicMock()
                m.blob_query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["mttd_mttr"]["avg_seconds_to_triaged"] == 2700  # (3600+1800)//2
            assert data["mttd_mttr"]["avg_seconds_to_resolved"] == 6300  # (7200+5400)//2
            assert data["mttd_mttr"]["sample_size"] == 2

    @pytest.mark.asyncio
    async def test_posture_incidents(self):
        """Incidents section populates total and by_state."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Incidents':
                mock_client = MagicMock()
                mock_client.crowdscore.return_value = {"status_code": 200, "body": {"resources": []}}
                def mock_query_incidents(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "status:'reopened'" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                    elif "status:'open'" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 5}}}}
                    elif "status:'closed'" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 3}}}}
                    return {"status_code": 200, "body": {"resources": ["i1"], "meta": {"pagination": {"total": 10}}}}
                mock_client.query_incidents.side_effect = mock_query_incidents
                mock_client.get_incidents.return_value = {
                    "status_code": 200,
                    "body": {"resources": [{"tactics": ["Execution", "Persistence"]}, {"tactics": ["Execution"]}]}
                }
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'ExposureManagement':
                m = MagicMock()
                m.blob_query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["incidents"]["total"] == 10
            assert data["incidents"]["by_state"]["Open"] == 5
            assert data["incidents"]["by_state"]["Closed"] == 3
            assert "Reopened" not in data["incidents"]["by_state"]  # 0 count excluded
            assert data["incidents"]["by_tactic"]["Execution"] == 2

    @pytest.mark.asyncio
    async def test_posture_sensor_health(self):
        """Sensor health reports RFM count and top versions."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Hosts':
                mock_client = MagicMock()
                def mock_query_devices(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "reduced_functionality_mode" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 2}}}}
                    return {"status_code": 200, "body": {"resources": ["h1", "h2"], "meta": {"pagination": {"total": 50}}}}
                mock_client.query_devices_by_filter.side_effect = mock_query_devices
                mock_client.get_device_details.return_value = {
                    "status_code": 200,
                    "body": {"resources": [
                        {"agent_version": "7.10.0"},
                        {"agent_version": "7.10.0"},
                    ]}
                }
                mock_client.query_devices.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Incidents':
                m = MagicMock()
                m.crowdscore.return_value = {"status_code": 200, "body": {"resources": []}}
                m.query_incidents.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'ExposureManagement':
                m = MagicMock()
                m.blob_query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["sensor_health"]["rfm_count"] == 2
            assert data["sensor_health"]["total_managed"] == 50
            assert "7.10.0" in data["sensor_health"]["by_version"]

    @pytest.mark.asyncio
    async def test_posture_asset_inventory(self):
        """Asset inventory via Discover API populates managed/unmanaged/iot/accounts."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Discover':
                mock_client = MagicMock()
                def mock_query_hosts(**kwargs):
                    fql = kwargs.get("filter", "")
                    if "managed" in fql and "unmanaged" not in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 500}}}}
                    elif "unmanaged" in fql:
                        return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 100}}}}
                    return {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                mock_client.query_hosts.side_effect = mock_query_hosts
                mock_client.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 25}}}}
                mock_client.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 300}}}}
                mock_client.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 1000}}}}
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Incidents':
                m = MagicMock()
                m.crowdscore.return_value = {"status_code": 200, "body": {"resources": []}}
                m.query_incidents.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'ExposureManagement':
                m = MagicMock()
                m.blob_query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_external_assets.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["asset_inventory"]["managed_hosts"] == 500
            assert data["asset_inventory"]["unmanaged_hosts"] == 100
            assert data["asset_inventory"]["iot_assets"] == 25
            assert data["asset_inventory"]["accounts"] == 300
            assert data["asset_inventory"]["applications"] == 1000

    @pytest.mark.asyncio
    async def test_posture_external_attack_surface(self):
        """External attack surface via ExposureManagement API."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'ExposureManagement':
                mock_client = MagicMock()
                mock_client.query_external_assets.return_value = {
                    "status_code": 200,
                    "body": {"resources": [], "meta": {"pagination": {"total": 2439}}}
                }
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Incidents':
                m = MagicMock()
                m.crowdscore.return_value = {"status_code": 200, "body": {"resources": []}}
                m.query_incidents.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert data["external_attack_surface"]["total_assets"] == 2439

    @pytest.mark.asyncio
    async def test_posture_missing_scopes(self):
        """403 responses populate missing_scopes list."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Incidents':
                mock_client = MagicMock()
                mock_client.crowdscore.return_value = {"status_code": 403, "body": {}}
                mock_client.query_incidents.return_value = {"status_code": 403, "body": {}}
                return mock_client
            elif name == 'ExposureManagement':
                mock_client = MagicMock()
                mock_client.query_external_assets.return_value = {"status_code": 403, "body": {}}
                return mock_client
            elif name == 'Alerts':
                return self._alerts_mock()
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name == 'Discover':
                m = MagicMock()
                m.query_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_iot_hosts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_accounts.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                m.query_applications.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            assert "Incidents:read" in data["missing_scopes"]
            assert "Exposure Management:read" in data["missing_scopes"]
            # Verify api_scopes has entries with correct statuses
            scope_map = {s["scope"]: s["status"] for s in data.get("api_scopes", [])}
            assert scope_map.get("Incidents:read") == "Missing"
            assert scope_map.get("Exposure Management:read") == "Missing"
            assert scope_map.get("Alerts:read") == "Active"

    @pytest.mark.asyncio
    async def test_posture_optional_graceful_failure(self):
        """New API sections failing gracefully don't break existing sections."""
        def make_mock_client(service_class):
            name = getattr(service_class, '__name__', '')
            if name == 'Alerts':
                return self._alerts_mock({"Critical": 5, "High": 10})
            elif name == 'CaseManagement':
                m = MagicMock()
                m.query_case_ids.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 2}}}}
                return m
            elif name == 'SpotlightVulnerabilities':
                m = MagicMock()
                m.query_vulnerabilities.return_value = {"status_code": 200, "body": {"resources": [], "meta": {"pagination": {"total": 0}}}}
                return m
            elif name == 'Hosts':
                return self._hosts_mock()
            elif name in ('Incidents', 'Discover', 'ExposureManagement'):
                raise Exception(f"Simulated failure for {name}")
            return MagicMock()

        with patch("crwd_mcp_server.get_falcon_client", side_effect=make_mock_client):
            from crwd_mcp_server import get_security_posture
            result = await get_security_posture(hours=24)
            data = json.loads(result)
            # Existing sections still work
            assert data["risk_score"] >= 0
            assert "risk_level" in data
            assert data["alerts"]["by_severity"].get("Critical", 0) == 5
            # New sections have error info but don't crash
            assert data["crowdscore"]["error"] is not None
            assert data["incidents"]["error"] is not None
            assert data["asset_inventory"]["error"] is not None
            assert data["external_attack_surface"]["error"] is not None


# ---------------------------------------------------------------------------
# 10. search_hosts
# ---------------------------------------------------------------------------

class TestSearchHosts:
    """Tests for the search_hosts tool."""

    @pytest.mark.asyncio
    async def test_search_hosts_basic(self, mock_hosts_response, mock_host_details):
        """Basic host search returns valid JSON with expected fields."""
        mock_hosts_response["body"]["meta"] = {"pagination": {"total": 1}}
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = mock_hosts_response
        mock_client.get_device_details.return_value = mock_host_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_hosts
            result = await search_hosts()
            data = json.loads(result)
            assert "total_hosts" in data
            assert "hosts" in data
            assert data["total_hosts"] == 1
            assert len(data["hosts"]) == 1
            assert data["hosts"][0]["hostname"] == "test-host"
            assert data["hosts"][0]["platform"] == "Windows"

    @pytest.mark.asyncio
    async def test_search_hosts_with_platform_filter(self, mock_hosts_response, mock_host_details):
        """Host search applies platform filter correctly."""
        mock_hosts_response["body"]["meta"] = {"pagination": {"total": 1}}
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = mock_hosts_response
        mock_client.get_device_details.return_value = mock_host_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_hosts
            result = await search_hosts(platform="Windows")
            data = json.loads(result)
            assert data["total_hosts"] == 1
            # Verify filter was applied
            call_args = mock_client.query_devices_by_filter.call_args
            assert "Windows" in call_args[1]["filter"]

    @pytest.mark.asyncio
    async def test_search_hosts_with_last_seen_within(self, mock_hosts_response, mock_host_details):
        """Host search applies last_seen_within filter correctly."""
        mock_hosts_response["body"]["meta"] = {"pagination": {"total": 1}}
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = mock_hosts_response
        mock_client.get_device_details.return_value = mock_host_details

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_hosts
            result = await search_hosts(last_seen_within=7)
            data = json.loads(result)
            assert data["total_hosts"] == 1
            call_args = mock_client.query_devices_by_filter.call_args
            assert "last_seen:>" in call_args[1]["filter"]

    @pytest.mark.asyncio
    async def test_search_hosts_no_results(self):
        """Host search with no results returns empty list."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_hosts
            result = await search_hosts(hostname="nonexistent")
            data = json.loads(result)
            assert data["total_hosts"] == 0
            assert data["hosts"] == []

    @pytest.mark.asyncio
    async def test_search_hosts_api_error(self):
        """Host search handles API errors gracefully."""
        mock_client = MagicMock()
        mock_client.query_devices_by_filter.side_effect = Exception("Hosts API down")

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_client):
            from crwd_mcp_server import search_hosts
            result = await search_hosts()
            data = json.loads(result)
            assert "error" in data
