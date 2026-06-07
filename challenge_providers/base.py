from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ChallengeResult:
    status: str
    provider: str
    challenge_type: str = "unknown"
    reason: str = ""
    cost: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def cleared(self) -> bool:
        return self.status == "cleared"


class ChallengeProvider:
    name = "base"

    def can_handle(self, challenge_type: str, evidence: Dict[str, Any]) -> bool:
        return False

    def solve(self, page, controller, evidence: Optional[Dict[str, Any]] = None) -> ChallengeResult:
        raise NotImplementedError
