"""Unit tests for NGSIEM, Identity Protection, Cloud Security, and Exposure Management tools.

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


# ---------------------------------------------------------------------------
# NGSIEM Ingestion
# ---------------------------------------------------------------------------

class TestGetNGSIEMIngestion:
    """Tests for the get_ngsiem_ingestion tool."""

    @pytest.mark.asyncio
    async def test_ngsiem_basic(self):
        """NGSIEM ingestion returns structured result with totals and sources."""
        mock_fc = MagicMock()
        mock_fc.query_children.return_value = {"status_code": 403, "body": {}}

        mock_ngsiem = MagicMock()
        mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {
                "id": "job-1",
                "done": True,
                "events": [
                    {"#Vendor": "CrowdStrike", "_sum": 1048576, "_count": 500},
                    {"#Vendor": "Okta", "_sum": 524288, "_count": 200},
                ]
            }
        }

        def mock_client(cls):
            name = cls.__name__ if hasattr(cls, '__name__') else str(cls)
            if "FlightControl" in name:
                return mock_fc
            return mock_ngsiem

        with patch("crwd_mcp_server.get_falcon_client", side_effect=mock_client):
            from crwd_mcp_server import get_ngsiem_ingestion
            result = await get_ngsiem_ingestion(hours=24)
            data = json.loads(result)
            assert "total_bytes" in data
            assert "total_events" in data
            assert "sources" in data
            assert data["error"] is None

    @pytest.mark.asyncio
    async def test_ngsiem_scope_forbidden(self):
        """NGSIEM returns error when scope is not available."""
        mock_fc = MagicMock()
        mock_fc.query_children.return_value = {"status_code": 403, "body": {}}

        mock_ngsiem = MagicMock()
        mock_ngsiem.start_search.return_value = {
            "status_code": 403,
            "resources": {"errors": [{"message": "Forbidden"}]}
        }

        def mock_client(cls):
            name = cls.__name__ if hasattr(cls, '__name__') else str(cls)
            if "FlightControl" in name:
                return mock_fc
            return mock_ngsiem

        with patch("crwd_mcp_server.get_falcon_client", side_effect=mock_client):
            from crwd_mcp_server import get_ngsiem_ingestion
            result = await get_ngsiem_ingestion(hours=24)
            data = json.loads(result)
            assert data["total_bytes"] == 0
            assert data["total_events"] == 0


# ---------------------------------------------------------------------------
# Identity Protection
# ---------------------------------------------------------------------------

class TestGetIdentityProtection:
    """Tests for the get_identity_protection tool."""

    @pytest.mark.asyncio
    async def test_identity_basic(self):
        """Identity Protection returns sensor counts and risky entities."""
        mock_idp = MagicMock()
        mock_idp.query_sensors_by_filter.return_value = {
            "status_code": 200,
            "body": {"meta": {"pagination": {"total": 42}}}
        }
        mock_idp.get_sensor_aggregates.return_value = {
            "status_code": 200,
            "body": {"resources": [{"buckets": [
                {"label": "Active", "count": 30},
                {"label": "Inactive", "count": 12},
            ]}]}
        }
        mock_idp.graphql.return_value = {
            "status_code": 200,
            "body": {"resources": [{
                "entities": [
                    {"primaryDisplayName": "jdoe", "riskScore": 85, "entityType": "user",
                     "riskFactors": [{"severity": "HIGH", "type": "UNUSUAL_LOGIN"}]}
                ]
            }]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_idp):
            from crwd_mcp_server import get_identity_protection
            result = await get_identity_protection(limit=10)
            data = json.loads(result)
            assert data["total_sensors"] == 42
            assert data["error"] is None
            assert "by_status" in data
            assert "risky_entities" in data

    @pytest.mark.asyncio
    async def test_identity_scope_forbidden(self):
        """Identity Protection returns error on 403."""
        mock_idp = MagicMock()
        mock_idp.query_sensors_by_filter.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_idp):
            from crwd_mcp_server import get_identity_protection
            result = await get_identity_protection(limit=10)
            data = json.loads(result)
            assert data["error"] is not None
            assert "403" in data["error"]


# ---------------------------------------------------------------------------
# Cloud Security
# ---------------------------------------------------------------------------

class TestGetCloudSecurity:
    """Tests for the get_cloud_security tool."""

    @pytest.mark.asyncio
    async def test_cloud_security_basic(self):
        """Cloud Security returns risks by severity, provider, service."""
        mock_cs = MagicMock()
        mock_cs.combined_cloud_risks.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"severity": "High", "cloud_provider": "AWS", "service_category": "S3",
                     "status": "open", "asset_type": "bucket", "rule_name": "Public Bucket",
                     "account_name": "prod-account"},
                    {"severity": "Critical", "cloud_provider": "Azure", "service_category": "VM",
                     "status": "open", "asset_type": "instance", "rule_name": "Open SSH",
                     "account_name": "dev-account"},
                ],
                "meta": {"pagination": {"total": 2}}
            }
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_cs):
            with patch("crwd_mcp_server.CloudSecurityDetections", None):
                from crwd_mcp_server import get_cloud_security
                result = await get_cloud_security(limit=10)
                data = json.loads(result)
                assert data["total_risks"] == 2
                assert "High" in data["risks_by_severity"]
                assert "Critical" in data["risks_by_severity"]
                assert "AWS" in data["risks_by_provider"]
                assert "Azure" in data["risks_by_provider"]
                assert data["error"] is None
                assert len(data["top_risks"]) == 2

    @pytest.mark.asyncio
    async def test_cloud_security_with_severity_filter(self):
        """Cloud Security filters by severity when provided."""
        mock_cs = MagicMock()
        mock_cs.combined_cloud_risks.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"severity": "Critical", "cloud_provider": "AWS", "service_category": "IAM",
                     "status": "open", "asset_type": "role", "rule_name": "Overprivileged Role",
                     "account_name": "prod"},
                ],
                "meta": {"pagination": {"total": 1}}
            }
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_cs):
            with patch("crwd_mcp_server.CloudSecurityDetections", None):
                from crwd_mcp_server import get_cloud_security
                result = await get_cloud_security(severity="Critical", limit=10)
                data = json.loads(result)
                assert data["total_risks"] == 1
                # Verify filter was passed
                call_kwargs = mock_cs.combined_cloud_risks.call_args[1]
                assert "severity:'Critical'" in call_kwargs.get("filter", "")

    @pytest.mark.asyncio
    async def test_cloud_security_scope_forbidden(self):
        """Cloud Security returns error on 403."""
        mock_cs = MagicMock()
        mock_cs.combined_cloud_risks.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_cs):
            from crwd_mcp_server import get_cloud_security
            result = await get_cloud_security(limit=10)
            data = json.loads(result)
            assert data["error"] is not None
            assert "403" in data["error"]


# ---------------------------------------------------------------------------
# Exposure Management
# ---------------------------------------------------------------------------

class TestGetExposureManagement:
    """Tests for the get_exposure_management tool."""

    @pytest.mark.asyncio
    async def test_exposure_basic(self):
        """Exposure Management returns asset counts and breakdowns."""
        mock_em = MagicMock()
        mock_em.query_external_assets.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["asset-1", "asset-2"],
                "meta": {"pagination": {"total": 25}}
            }
        }
        mock_em.aggregate_external_assets.return_value = {
            "status_code": 200,
            "body": {"resources": [{"buckets": [
                {"label": "Critical", "count": 5},
                {"label": "High", "count": 10},
                {"label": "Medium", "count": 10},
            ]}]}
        }
        mock_em.get_external_assets.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "asset-1", "name": "api.example.com", "asset_type": "DOMAIN",
                 "criticality": "Critical", "connectivity": {"ip": {"addresses": [{"ip": "1.2.3.4"}]}},
                 "discovery": {"first_seen": "2026-01-01T00:00:00Z"}},
                {"id": "asset-2", "name": "web.example.com", "asset_type": "IP_ADDRESS",
                 "criticality": "High", "connectivity": {"ip": {"addresses": [{"ip": "5.6.7.8"}]}},
                 "discovery": {"first_seen": "2026-02-01T00:00:00Z"}},
            ]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_em):
            from crwd_mcp_server import get_exposure_management
            result = await get_exposure_management(limit=10)
            data = json.loads(result)
            assert data["total_assets"] == 25
            assert data["error"] is None
            assert len(data["assets"]) >= 1

    @pytest.mark.asyncio
    async def test_exposure_scope_forbidden(self):
        """Exposure Management returns error on 403."""
        mock_em = MagicMock()
        mock_em.query_external_assets.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_em):
            from crwd_mcp_server import get_exposure_management
            result = await get_exposure_management(limit=10)
            data = json.loads(result)
            assert data["error"] is not None
            assert "403" in data["error"]

    @pytest.mark.asyncio
    async def test_exposure_empty_results(self):
        """Exposure Management handles no assets gracefully."""
        mock_em = MagicMock()
        mock_em.query_external_assets.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"total": 0}}
            }
        }
        mock_em.aggregate_external_assets.return_value = {
            "status_code": 200,
            "body": {"resources": [{"buckets": []}]}
        }

        with patch("crwd_mcp_server.get_falcon_client", return_value=mock_em):
            from crwd_mcp_server import get_exposure_management
            result = await get_exposure_management(limit=10)
            data = json.loads(result)
            assert data["total_assets"] == 0
            assert data["assets"] == []
            assert data["error"] is None


# ---------------------------------------------------------------------------
# API Client — Provider Translation
# ---------------------------------------------------------------------------

class TestAPIClientProviderTranslation:
    """Tests for multi-provider LLM request/response translation."""

    def test_to_alternate_provider_request(self):
        """Native messages are correctly translated to alternate provider format."""
        with patch.dict(os.environ, {"LLM_PROVIDER": "openai", "LLM_ENDPOINT": "https://test.example.com", "LLM_API_KEY": "test"}):
            # Force reimport to pick up env
            import importlib
            import mcp_api_client
            importlib.reload(mcp_api_client)
            from mcp_api_client import _to_openai_request

            messages = [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": [{"type": "text", "text": "Hi there"}]}
            ]
            tools = [{
                "name": "test_tool",
                "description": "A test tool",
                "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}
            }]

            url_path, payload = _to_openai_request(messages, tools, "gpt-4o", max_tokens=1024)
            assert url_path == "/v1/chat/completions"
            assert payload["model"] == "gpt-4o"
            assert len(payload["messages"]) == 2
            assert payload["messages"][0]["role"] == "user"
            assert payload["tools"][0]["type"] == "function"
            assert payload["tools"][0]["function"]["name"] == "test_tool"

    def test_from_alternate_provider_response(self):
        """Alternate provider response is normalized to native format."""
        with patch.dict(os.environ, {"LLM_PROVIDER": "openai", "LLM_ENDPOINT": "https://test.example.com", "LLM_API_KEY": "test"}):
            import importlib
            import mcp_api_client
            importlib.reload(mcp_api_client)
            from mcp_api_client import _from_openai_response

            openai_data = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Here is the answer.",
                    },
                    "finish_reason": "stop"
                }]
            }

            result = _from_openai_response(openai_data)
            assert result["stop_reason"] == "end_turn"
            assert result["content"][0]["type"] == "text"
            assert result["content"][0]["text"] == "Here is the answer."

    def test_from_alternate_provider_tool_call(self):
        """Alternate provider tool call response is normalized correctly."""
        with patch.dict(os.environ, {"LLM_PROVIDER": "openai", "LLM_ENDPOINT": "https://test.example.com", "LLM_API_KEY": "test"}):
            import importlib
            import mcp_api_client
            importlib.reload(mcp_api_client)
            from mcp_api_client import _from_openai_response

            openai_data = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "search_alerts",
                                "arguments": '{"product": "epp", "hours": 24}'
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

            result = _from_openai_response(openai_data)
            assert result["stop_reason"] == "tool_use"
            assert result["content"][0]["type"] == "tool_use"
            assert result["content"][0]["name"] == "search_alerts"
            assert result["content"][0]["input"]["product"] == "epp"


# ---------------------------------------------------------------------------
# Config Validation
# ---------------------------------------------------------------------------

class TestConfigValidation:
    """Tests for configuration and environment validation."""

    def test_validate_config_missing_credentials(self):
        """Config validation raises on missing Falcon credentials."""
        with patch.dict(os.environ, {"FALCON_CLIENT_ID": "", "FALCON_CLIENT_SECRET": ""}, clear=False):
            import importlib
            import crwd_mcp_server
            importlib.reload(crwd_mcp_server)
            from crwd_mcp_server import validate_config, ConfigError
            with pytest.raises(ConfigError) as exc_info:
                validate_config()
            assert "FALCON_CLIENT_ID" in str(exc_info.value)

    def test_validate_config_valid(self):
        """Config validation passes with all required vars set."""
        env = {
            "FALCON_CLIENT_ID": "test-id",
            "FALCON_CLIENT_SECRET": "test-secret",
            "FALCON_BASE_URL": "https://api.crowdstrike.com",
            "LLM_ENDPOINT": "https://llm.example.com",
            "LLM_API_KEY": "test-key",
            "LLM_PROVIDER": "anthropic",
        }
        with patch.dict(os.environ, env, clear=False):
            import importlib
            import crwd_mcp_server
            importlib.reload(crwd_mcp_server)
            from crwd_mcp_server import validate_config
            # Should not raise
            validate_config()
