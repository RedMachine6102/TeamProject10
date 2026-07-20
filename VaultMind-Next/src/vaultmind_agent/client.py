from __future__ import annotations

import json
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from vaultmind_next.device import payload_digest

from .config import AgentConfig
from .identity import DeviceIdentity

Transport = Callable[[str, dict, dict[str, str]], dict | list]


class AgentApiError(RuntimeError):
    pass


class AgentApiClient:
    def __init__(self, config: AgentConfig, identity: DeviceIdentity,
                 transport: Transport | None = None):
        if config.agent_id != identity.agent_id:
            raise ValueError("agent config and device identity do not match")
        self.config = config
        self.identity = identity
        self._transport = transport

    def register(self, display_name: str, enrollment_code: str) -> dict:
        return self._post("/api/v1/devices/enroll", {
            "device_id": self.identity.agent_id,
            "display_name": display_name,
            "public_key": self.identity.public_key,
            "platform": "windows",
            "enrollment_code": enrollment_code,
        })

    def available_jobs(self) -> list[dict]:
        request = self.identity.signed_request("rotation.available", {})
        result = self._post("/api/v1/agent/jobs/available", request)
        return list(result)

    def claim(self, job_id: str, lease_seconds: int = 300) -> dict:
        job_id = self._job_id(job_id)
        values = {"job_id": job_id, "lease_seconds": lease_seconds}
        request = self.identity.signed_request("rotation.claim", values)
        request["lease_seconds"] = lease_seconds
        return self._post(f"/api/v1/agent/jobs/{job_id}/claim", request)

    def package(self, job_id: str) -> dict:
        job_id = self._job_id(job_id)
        request = self.identity.signed_request(
            "rotation.package", {"job_id": job_id}
        )
        return self._post(f"/api/v1/agent/jobs/{job_id}/package", request)

    def commit(self, job_id: str, envelope: dict) -> dict:
        job_id = self._job_id(job_id)
        values = {
            "job_id": job_id, "envelope_sha256": payload_digest(envelope),
        }
        request = self.identity.signed_request("rotation.commit", values)
        request["envelope"] = envelope
        return self._post(f"/api/v1/agent/jobs/{job_id}/commit", request)

    def fail(self, job_id: str, error_code: str) -> dict:
        job_id = self._job_id(job_id)
        values = {"job_id": job_id, "error_code": error_code}
        request = self.identity.signed_request("rotation.fail", values)
        request["error_code"] = error_code
        return self._post(f"/api/v1/agent/jobs/{job_id}/fail", request)

    @staticmethod
    def _job_id(value: str) -> str:
        if (
            not 8 <= len(value) <= 128
            or not value.replace("-", "").replace("_", "").isalnum()
        ):
            raise AgentApiError("rotation job id is invalid")
        return value

    def _post(self, path: str, body: dict,
              headers: dict[str, str] | None = None) -> dict | list:
        request_headers = {
            "Accept": "application/json", "Content-Type": "application/json",
            **(headers or {}),
        }
        if self._transport:
            return self._transport(path, body, request_headers)
        request = Request(
            f"{self.config.server_url}{path}",
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers=request_headers, method="POST",
        )
        try:
            with urlopen(request, timeout=20) as response:
                data = response.read(2_000_001)
        except HTTPError as exc:
            raise AgentApiError(f"VaultMind API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise AgentApiError("VaultMind API is unavailable") from exc
        if len(data) > 2_000_000:
            raise AgentApiError("VaultMind API response was too large")
        try:
            result = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AgentApiError("VaultMind API returned invalid JSON") from exc
        if not isinstance(result, (dict, list)):
            raise AgentApiError("VaultMind API returned an invalid response")
        return result
