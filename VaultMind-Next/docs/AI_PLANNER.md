# Unprivileged AI planner

The optional planner uses the OpenAI Responses API only to classify sanitized
security signals. It is disabled by default under the Compose `ai` profile and
will not start without an explicit `OPENAI_API_KEY`.

The request contains only provider, fixed event category, and sender domain. It
sets `store: false` and requires a strict JSON schema with three possible
recommendations: `ignore`, `review`, or `propose_rotation`. The default model is
configurable and currently set to `gpt-5.4-mini`, a smaller model suitable for
this bounded task. OpenAI's official model pages document Responses API and
structured-output support for the GPT-5 family:
[model catalog](https://developers.openai.com/api/docs/models/gpt) and
[GPT-5.4](https://developers.openai.com/api/docs/models/gpt-5.4).

A recommendation is data, not authority. The planner has no vault key, OAuth
token, passphrase, username, credential, device key, bearer token, job lease, or
API tool. It cannot approve a job or call the trusted-agent protocol. Existing
30/60/90-day policy, item-scoped grants, signed agent requests, and verified
provider login remain mandatory before any password update is committed.

Start the planner only after placing an API key in the VM's protected secret
environment:

```sh
docker compose --profile ai up -d planner
```

Production activation still requires prompt-injection evaluation, cost/rate
limits, alerting, a pinned model review process, and controlled-mailbox tests.
