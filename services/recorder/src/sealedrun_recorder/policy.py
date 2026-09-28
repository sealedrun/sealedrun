"""The recorder's one policy rule: labelled data must not reach a cloud target.

`SEALEDRUN_POLICY_BLOCK_TO_CLOUD='["nda"]'` names the data labels that block a call to a target
whose `location` is `cloud`. The proxies evaluate the rule before any upstream contact, refuse
the call to the client and seal a record with `outcome: blocked`, the SPEC 5.7 `policy` object
and the request that was not sent. A labelled cloud call the rule lets through carries an
`allow` decision, so the record shows that the rule was consulted. Local targets and calls made
while the rule is off carry no policy object at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

RULE_PREFIX = "recorder/no-"
DEFAULT_ALLOW = "default/allow"


@dataclass(frozen=True)
class Decision:
    """The SPEC 5.7 policy object for one call, and whether the call goes ahead."""

    rule_id: str
    decision: str
    reason: str

    @property
    def blocked(self) -> bool:
        """Whether the call must not be sent."""
        return self.decision == "block"

    def document(self) -> dict[str, Any]:
        """Return the `policy` object of the record."""
        return {"rule_id": self.rule_id, "decision": self.decision, "reason": self.reason}


@dataclass(frozen=True)
class Rule:
    """Labels that must not be sent to a `cloud` target; empty means the rule is off."""

    block_to_cloud: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        """Whether any label is configured."""
        return bool(self.block_to_cloud)

    def evaluate(self, target_location: str, labels: list[str]) -> Decision | None:
        """Decide one call; None when the rule does not apply (off, or not a cloud target)."""
        if not self.active or target_location != "cloud":
            return None
        for label in self.block_to_cloud:
            if label in labels:
                return Decision(
                    rule_id=f"{RULE_PREFIX}{label}-to-cloud",
                    decision="block",
                    reason=f"target.location=cloud and labels contain {label}",
                )
        return Decision(
            rule_id=DEFAULT_ALLOW,
            decision="allow",
            reason="target.location=cloud and no configured label is present",
        )
