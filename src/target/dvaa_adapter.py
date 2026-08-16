"""
DVAA OpenAI-compatible target adapter.

This adapter is responsible only for communicating with DVAA.
It does NOT decide whether an attack succeeded.

That decision belongs to the vulnerability detector.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class DVAAConnectionError(Exception):
    """Raised when a DVAA target cannot be reached."""


class DVAAResponseError(Exception):
    """Raised when DVAA returns an invalid/unexpected response."""


class DVAAOpenAIAdapter:

    def __init__(
        self,
        endpoint: str,
        target_name: str,
        timeout: int = 20,
    ):
        self.endpoint = endpoint
        self.target_name = target_name
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Check whether the DVAA agent is reachable.

        DVAA exposes /health on its agent ports.
        """

        health_url = self.endpoint.replace(
            "/v1/chat/completions",
            "/health"
        )

        request = urllib.request.Request(
            health_url,
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                body = response.read().decode("utf-8")

                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    data = {"raw": body}

                return {
                    "reachable": True,
                    "status_code": response.status,
                    "data": data,
                }

        except (urllib.error.URLError, TimeoutError) as exc:

            return {
                "reachable": False,
                "status_code": None,
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Send message
    # ------------------------------------------------------------------

    def send_message(
        self,
        message: str,
        conversation: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Send a user message to the DVAA OpenAI-compatible endpoint.

        conversation can be supplied for multi-turn attacks.
        """

        if conversation is None:
            messages = [
                {
                    "role": "user",
                    "content": message,
                }
            ]
        else:
            messages = list(conversation)

            messages.append(
                {
                    "role": "user",
                    "content": message,
                }
            )

        payload = {
            "messages": messages,
        }

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                body = response.read().decode("utf-8")

                try:
                    data = json.loads(body)
                except json.JSONDecodeError as exc:
                    raise DVAAResponseError(
                        f"DVAA returned invalid JSON: {body[:500]}"
                    ) from exc

                return {
                    "target": self.target_name,
                    "status_code": response.status,
                    "raw": data,
                    "message": self._extract_message(data),
                    "tool_calls": self._extract_tool_calls(data),
                }

        except urllib.error.HTTPError as exc:

            error_body = exc.read().decode("utf-8", errors="replace")

            raise DVAAConnectionError(
                f"{self.target_name} returned HTTP {exc.code}: "
                f"{error_body[:500]}"
            ) from exc

        except (urllib.error.URLError, TimeoutError) as exc:

            raise DVAAConnectionError(
                f"Could not reach {self.target_name}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Response normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_message(response: Dict[str, Any]) -> str:
        """
        Extract assistant text from an OpenAI-compatible response.
        """

        try:
            message = response["choices"][0]["message"]

            content = message.get("content")

            if content is None:
                return ""

            if isinstance(content, str):
                return content

            return str(content)

        except (KeyError, IndexError, TypeError):

            return ""

    @staticmethod
    def _extract_tool_calls(
        response: Dict[str, Any]
    ) -> list:

        try:
            return (
                response["choices"][0]
                ["message"]
                .get("tool_calls", [])
            )

        except (KeyError, IndexError, TypeError):

            return []

    # ------------------------------------------------------------------
    # Basic reconnaissance
    # ------------------------------------------------------------------
    def recon(self) -> Dict[str, Any]:
        """
        Perform non-destructive reconnaissance using DVAA's
        health metadata.

        We prefer target-provided metadata over asking the LLM
        to describe itself because the latter may be incomplete
        or intentionally unhelpful.
        """

        health = self.health_check()

        if not health["reachable"]:
            return {
                "target": self.target_name,
                "reachable": False,
                "capabilities": [],
                "attack_surfaces": [],
                "metadata": {},
                "error": health.get("error"),
            }

        metadata = health.get("data", {})

        capabilities = metadata.get("tools", [])

        return {
            "target": self.target_name,
            "reachable": True,

            "metadata": {
                "agent": metadata.get("agent"),
                "id": metadata.get("id"),
                "protocol": metadata.get("protocol"),
                "security_level": metadata.get("securityLevel"),
                "description": metadata.get("description"),
            },

            "capabilities": capabilities,

            "attack_surfaces": self._infer_attack_surfaces(
                capabilities
            ),
        }


    @staticmethod
    def _infer_attack_surfaces(capabilities):
        """
        Infer candidate attack surfaces from discovered capabilities.

        This is reconnaissance only. It does not claim that a
        vulnerability exists.
        """

        surfaces = []

        capability_map = {
            "read_file": [
                "file_access",
                "sensitive_information_disclosure",
                "tool_abuse",
            ],

            "write_file": [
                "file_write",
                "tool_abuse",
                "excessive_agency",
            ],

            "search_web": [
                "external_content",
                "indirect_prompt_injection",
                "information_disclosure",
            ],
        }

        for capability in capabilities:
            for surface in capability_map.get(
                capability,
                []
            ):
                if surface not in surfaces:
                    surfaces.append(surface)

        # Every LLM agent has an instruction-processing surface.
        surfaces.append("prompt_injection")

        return surfaces