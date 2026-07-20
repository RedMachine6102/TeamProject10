import json
from datetime import datetime, timezone

from vaultmind_next.models import EmailSecurityEvent
from vaultmind_next.planner import OpenAIPlanner, PLAN_SCHEMA


class FakePlanner(OpenAIPlanner):
    def __init__(self):
        super().__init__("test-api-key-with-enough-characters", "gpt-5.4-mini")
        self.request = None

    def _post(self, body):
        self.request = body
        return {"output": [{"content": [{
            "type": "output_text",
            "text": json.dumps({
                "action": "propose_rotation", "risk": "high",
                "reason_code": "possible_compromise",
            }),
        }]}]}


def test_ai_planner_receives_only_sanitized_metadata_and_has_no_authority():
    event = EmailSecurityEvent(
        event_id="e" * 64, provider="google", category="suspicious_signin",
        source_domain="example.com", occurred_at=datetime.now(timezone.utc),
        detected_at=datetime.now(timezone.utc),
    )
    planner = FakePlanner()
    result = planner.plan(event)
    sent = json.loads(planner.request["input"])
    assert sent == {
        "category": "suspicious_signin", "provider": "google",
        "source_domain": "example.com",
    }
    assert "event_id" not in sent
    assert planner.request["store"] is False
    assert planner.request["text"]["format"]["strict"] is True
    assert PLAN_SCHEMA["additionalProperties"] is False
    assert result.action == "propose_rotation"
    assert not hasattr(result, "approved")
    assert not hasattr(result, "credential")
