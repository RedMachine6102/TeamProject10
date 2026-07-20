from __future__ import annotations

import argparse
import getpass
import sys
import time
from uuid import uuid4

from .adapters import HttpProviderAdapter, VerifiedRotationExecutor
from .client import AgentApiClient, AgentApiError
from .config import AgentConfig, AgentPaths
from .email_challenge import LocalEmailCodeSource, LocalEmailCredentials
from .identity import DeviceIdentity
from .recovery import DpapiPendingRotationStore
from .runner import RotationOutcome, TrustedAgentRunner


def _adapter_values(values: list[str]) -> tuple[list[str], dict[str, str]]:
    providers: list[str] = []
    urls: dict[str, str] = {}
    for value in values:
        provider, separator, url = value.partition("=")
        provider = provider.strip().lower()
        if not separator or not provider or not url:
            raise ValueError("adapter must use provider=https://adapter.example")
        providers.append(provider)
        urls[provider] = url
    return providers, urls


def _sender_domain_values(values: list[str]) -> dict[str, list[str]]:
    domains: dict[str, list[str]] = {}
    for value in values:
        provider, separator, domain = value.partition("=")
        provider = provider.strip().lower()
        domain = domain.strip().lower()
        if not separator or not provider or not domain:
            raise ValueError(
                "sender domain must use rotation-provider=mail.example"
            )
        domains.setdefault(provider, []).append(domain)
    return domains


def enroll(args: argparse.Namespace, paths: AgentPaths) -> int:
    if paths.config.exists() or paths.device_key.exists():
        raise RuntimeError("agent is already enrolled")
    providers, urls = _adapter_values(args.adapter)
    config = AgentConfig(
        server_url=args.server, agent_id=args.agent_id,
        allowed_providers=providers, adapter_urls=urls,
    )
    identity = DeviceIdentity.generate(args.agent_id)
    client = AgentApiClient(config, identity)
    enrollment_code = getpass.getpass("VaultMind device enrollment code: ")
    client.register(args.name, enrollment_code)
    identity.save(paths.device_key)
    config.save(paths.config)
    print(f"Enrolled trusted agent {config.agent_id}.")
    return 0


def build_runner(paths: AgentPaths) -> TrustedAgentRunner:
    config = AgentConfig.load(paths.config)
    identity = DeviceIdentity.load(config.agent_id, paths.device_key)
    client = AgentApiClient(config, identity)
    adapters = [
        HttpProviderAdapter(provider, url)
        for provider, url in config.adapter_urls.items()
    ]
    code_source = None
    if paths.email_credentials.exists():
        credentials = LocalEmailCredentials.load(paths.email_credentials)
        code_source = LocalEmailCodeSource(credentials)
    return TrustedAgentRunner(
        config, client, VerifiedRotationExecutor(adapters, code_source),
        paths.pause_file, DpapiPendingRotationStore(paths.pending_rotation),
    )


def print_outcome(outcome: RotationOutcome) -> int:
    if outcome.status == "succeeded":
        print(f"Rotation {outcome.job_id} completed and verified.")
        return 0
    if outcome.status in {"idle", "paused"}:
        print(f"Agent is {outcome.status}.")
        return 0
    if outcome.status in {"pending", "recovery_required"}:
        print(
            f"Rotation {outcome.job_id} needs reconciliation: "
            f"{outcome.error_code}.",
            file=sys.stderr,
        )
        return 2
    print(f"Rotation failed safely: {outcome.error_code}.", file=sys.stderr)
    return 1


def run_once(paths: AgentPaths) -> int:
    runner = build_runner(paths)
    passphrase = getpass.getpass("Vault passphrase: ")
    try:
        return print_outcome(runner.run_once(passphrase))
    finally:
        del passphrase


def run_loop(runner: TrustedAgentRunner, passphrase: str,
             poll_seconds: int) -> int:
    if not 15 <= poll_seconds <= 3600:
        raise ValueError("poll interval must be 15 to 3600 seconds")
    while True:
        outcome = runner.run_once(passphrase)
        result = print_outcome(outcome)
        if outcome.status == "recovery_required":
            return result
        time.sleep(poll_seconds)


def run_forever(paths: AgentPaths, poll_seconds: int) -> int:
    runner = build_runner(paths)
    passphrase = getpass.getpass("Vault passphrase: ")
    print("Trusted agent is running. Press Ctrl+C to stop.")
    try:
        return run_loop(runner, passphrase, poll_seconds)
    except KeyboardInterrupt:
        print("\nTrusted agent stopped.")
        return 0
    finally:
        del passphrase


def configure_email(args: argparse.Namespace, paths: AgentPaths) -> int:
    credentials = LocalEmailCredentials(
        provider=args.mail_provider,
        client_id=args.client_id.strip(),
        client_secret=getpass.getpass(
            "OAuth client secret (leave blank for a public client): "
        ),
        refresh_token=getpass.getpass("OAuth refresh token: "),
        sender_domains=_sender_domain_values(args.sender_domain),
    )
    credentials.save(paths.email_credentials)
    print("Local email verification configured.")
    return 0


def email_status(paths: AgentPaths) -> int:
    if not paths.email_credentials.exists():
        print("Local email verification is not configured.")
        return 0
    credentials = LocalEmailCredentials.load(paths.email_credentials)
    allowed = ", ".join(
        f"{provider}={','.join(domains)}"
        for provider, domains in credentials.sender_domains.items()
    )
    print(f"Local email provider={credentials.provider}; senders={allowed}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultmind-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    enroll_parser = subparsers.add_parser("enroll")
    enroll_parser.add_argument("--server", required=True)
    enroll_parser.add_argument("--name", default="VaultMind Windows Agent")
    enroll_parser.add_argument("--agent-id", default=f"agent-{uuid4()}")
    enroll_parser.add_argument(
        "--adapter", action="append", default=[],
        help="allowlist entry such as demo=https://adapter.example",
    )
    subparsers.add_parser("run-once")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--poll-seconds", type=int, default=60)
    subparsers.add_parser("pause")
    subparsers.add_parser("resume")
    subparsers.add_parser("status")
    email_parser = subparsers.add_parser("email-configure")
    email_parser.add_argument(
        "--mail-provider", required=True, choices=["google", "microsoft"]
    )
    email_parser.add_argument("--client-id", required=True)
    email_parser.add_argument(
        "--sender-domain", action="append", required=True,
        help="allowlist entry such as demo=accounts.example",
    )
    subparsers.add_parser("email-status")
    subparsers.add_parser("email-disconnect")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    paths = AgentPaths.default()
    try:
        if args.command == "enroll":
            return enroll(args, paths)
        if args.command == "run-once":
            return run_once(paths)
        if args.command == "run":
            return run_forever(paths, args.poll_seconds)
        if args.command == "email-configure":
            return configure_email(args, paths)
        if args.command == "email-status":
            return email_status(paths)
        if args.command == "email-disconnect":
            paths.email_credentials.unlink(missing_ok=True)
            print("Local email verification disconnected.")
            return 0
        if args.command == "pause":
            paths.directory.mkdir(parents=True, exist_ok=True)
            paths.pause_file.write_text("paused\n", encoding="utf-8")
            print("Agent paused.")
            return 0
        if args.command == "resume":
            paths.pause_file.unlink(missing_ok=True)
            print("Agent resumed.")
            return 0
        config = AgentConfig.load(paths.config)
        if paths.pause_file.exists():
            state = "paused"
        elif paths.pending_rotation.exists():
            state = "recovery pending"
        else:
            state = "ready"
        print(f"{config.agent_id}: {state}; providers={config.allowed_providers}")
        return 0
    except (AgentApiError, OSError, RuntimeError, ValueError) as exc:
        print(f"Agent error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
