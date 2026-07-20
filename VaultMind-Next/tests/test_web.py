from pathlib import Path


WEB_ROOT = Path(__file__).parents[1] / "web"


def test_automatic_rotation_form_creates_scoped_agent_grant():
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    form_handler = script.split(
        'document.querySelector("#credential-form")', 1
    )[1]

    assert 'id="credential-agent"' in html
    assert 'id="credential-grant-days"' in html
    assert 'device.status === "active"' in script
    assert 'api("/api/v1/automation/grants"' in form_handler
    assert 'approvalMode === "automatic"' in form_handler
    assert "/api/v1/vault/items/${encodeURIComponent(itemId)}" in form_handler
    assert "toggle-policy" in script
    assert "revoke-grant" in script
    assert 'data-action="approve"' in script
    assert 'data-action="cancel"' in script
    assert "escapeAttribute" in script
