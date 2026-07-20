import os

from .api import create_demo_provider

username = os.getenv("VAULTMIND_DEMO_USERNAME", "")
password = os.getenv("VAULTMIND_DEMO_PASSWORD", "")
if len(username) < 3 or len(password) < 16:
    raise RuntimeError("demo provider credentials must be explicitly configured")

app = create_demo_provider(username, password)
