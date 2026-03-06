"""
MFA Policy Manager

Policy evaluation utility for multi-factor authentication enforcement signals.
This module does not store secrets and only evaluates policy metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MFAMethod(Enum):
    PASSWORD = "password"
    TOTP = "totp"
    DEVICE_TOKEN = "device_token"
    PUSH = "push"


@dataclass
class MFAEvaluation:
    required: bool
    passed: bool
    missing_methods: list[str]
    reason: str


class MFAManager:
    """Evaluates MFA policy requirements for session/access events."""

    def __init__(self, privileged_roles: set[str] | None = None) -> None:
        self.privileged_roles = privileged_roles or {"admin", "security_admin", "infra_ops"}

    def evaluate(
        self,
        role: str,
        provided_methods: list[str] | None,
        is_vpn_access: bool,
    ) -> MFAEvaluation:
        provided = set(provided_methods or [])
        required = is_vpn_access or role in self.privileged_roles

        if not required:
            return MFAEvaluation(False, True, [], "MFA not required for this access")

        # Require at least two factors with one non-password factor.
        has_password = MFAMethod.PASSWORD.value in provided
        has_non_password = any(
            m in provided for m in [MFAMethod.TOTP.value, MFAMethod.DEVICE_TOKEN.value, MFAMethod.PUSH.value]
        )

        passed = has_password and has_non_password
        missing = []
        if not has_password:
            missing.append(MFAMethod.PASSWORD.value)
        if not has_non_password:
            missing.append("one_of_totp_or_device_token_or_push")

        return MFAEvaluation(
            required=True,
            passed=passed,
            missing_methods=missing,
            reason="MFA required for VPN/privileged access",
        )
