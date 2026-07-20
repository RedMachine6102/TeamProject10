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
    assert 'id="credential-provider"' in html
    assert 'device.status === "active"' in script
    assert 'api("/api/v1/automation/grants"' in form_handler
    assert 'approvalMode === "automatic"' in form_handler
    assert "/api/v1/vault/items/${encodeURIComponent(itemId)}" in form_handler
    assert "toggle-policy" in script
    assert "revoke-grant" in script
    assert 'data-action="approve"' in script
    assert 'data-action="cancel"' in script
    assert "escapeAttribute" in script
    assert '"#credential-provider"' in form_handler
    assert "site.hostname.split" not in form_handler


def test_unlocked_vault_has_explicit_secure_crud_controls():
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'id="edit-credential-dialog"' in html
    assert 'id="edit-credential-form"' in html
    assert 'data-action="reveal"' in script
    assert 'data-action="edit"' in script
    assert 'data-action="delete"' in script
    assert "record.data.password" in script
    assert "data-password" not in script
    assert "decryptedVaultRecords.clear()" in script
    assert 'editCredentialDialog.addEventListener("close"' in script
    assert "/api/v1/vault/items/${encodeURIComponent(record.item.item_id)}" in script
