# When the agent or its host is compromised

After a breach the question is "show what the agent did". This page is the order of work with a
SealedRun recorder: cut the agent off, take the evidence out, check it somewhere else, and
hand over one page that says what it covers. Every step is a command you can run today.

SealedRun records and proves; it does not detect an attack and does not stop one.
[TRUST.md](../TRUST.md) states what a bundle proves and what it does not, and the
[last section](#what-the-archive-does-not-prove) repeats the part that matters in an incident.

## Before anything happens

Three things cannot be done afterwards.

- Write down the recorder's `principal_id` (`GET /api/identity`) in a place the agent's host
  cannot write to: a contract, a ticket, a password manager. A verifier trusts a bundle only
  against an id it got from somewhere other than the bundle.
- Keep anchoring on (the default). With `SEALEDRUN_ANCHORS='["tsa","rekor"]'` each anchored
  head also lands in a public log that the operator of the recorder cannot edit.
- Run the recorder on a host the agent cannot log in to. A recorder on the agent's own host
  shares its fate: whoever takes the host takes the signing keys.

## 1. Cut the agent off

The recorder has one API token, used by every agent and by the API. Replace it and restart;
from that moment the old token is refused, so nothing more is recorded or proxied for whoever
holds it. Note the time: it is the moment your response started.

```bash
umask 077 && openssl rand -hex 32 > sealedrun-token.new
export SEALEDRUN_API_TOKEN="$(cat sealedrun-token.new)"
docker compose up -d --force-recreate sealedrun
date -u +%Y-%m-%dT%H:%M:%SZ
```

If the token lives in an `.env` file or a secret store, change it there instead of exporting
it. Runs that were open stay open and are exported as they stand. This does not revoke the
model provider keys the recorder holds; rotate those with the provider if the recorder's host
is in doubt.

## 2. Take the evidence out

Export everything recorded in the period as one archive. Start the window well before the
first suspicious action; runs are exported whole, so a run that began earlier comes with its
beginning. `note` is signed into the archive as you typed it: put the incident number and who
is asking.

```bash
curl -fsS -X POST -H "Authorization: Bearer $SEALEDRUN_API_TOKEN" -o evidence.zip \
  "http://127.0.0.1:8080/api/export?since=2026-11-11T06:00:00Z&until=2026-11-11T12:00:00Z&note=INC-42"
sha256sum evidence.zip
```

Copy `evidence.zip` off the host and write the SHA-256 where the host cannot reach it (the
incident ticket, an email to counsel). That line is what later shows the file was not swapped.

- One agent only: add `&label=<run label>`.
- Bodies hold personal data the reader does not need: add `&payloads=omit`. The records keep
  every digest and the bodies stay in the recorder.
- `413`: more than 1024 runs match; split the window and export each part.
- `404`: nothing was recorded in that window. That is a finding too: write it down.

## 3. Check it on another machine

Verify on a machine that was not part of the incident, with the principal id you wrote down
earlier, not one read from the recorder today.

```bash
pip install sealedrun
sha256sum evidence.zip
python -m sealedrun evidence.zip <principal id>
```

`OK … principal trusted` means every record, signature and chain link holds and the archive
was signed by your recorder. `FAIL` names the check and the record where it broke. Build the
timeline from this archive, not from files on the compromised host: open it in the Inspector
(the recorder's web page, or any copy of it) to read the steps in order, with what was sent
to which model or tool and what a human approved.

## 4. Write the one page

```bash
python -m sealedrun --report evidence.zip <principal id> > report.txt
```

`report.txt` states the result, the window you asked for, the period and the number of runs
and records, what an outside witness saw, each human approval with who gave it, the findings
and the SHA-256 of the file. The Inspector shows the same text under "Report". Attach it, with
the archive or its digest, to the notice or the claim. Read three lines before you send it:

- `Principal identity`: `NOT CONFIRMED` means you verified without the id you wrote down beforehand.
- `Not anchored`: records after the last witness-verified anchor. A person holding the
  recorder's keys could have rewritten those, and only those.
- `Findings`: steps outside the delegation's scope, or run without the approval their policy
  required. They do not break integrity; they are what the reader will ask about.

Deadlines the page is usually needed for. Check the text that applies to you; national rules
and your supervisor's templates add to these.

| Rule                                     | First notice                                                                                | Next                                         | Final report                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------- | ------------------------------------------------- |
| DORA, Delegated Regulation (EU) 2025/301 | 4 hours after the incident is classified as major, at most 24 hours after you became aware  | Intermediate report 72 hours after the first | One month after the latest intermediate report    |
| NIS2, Directive (EU) 2022/2555 art. 23   | Early warning within 24 hours of becoming aware of a significant incident                   | Incident notification within 72 hours        | One month after the incident notification         |
| EU AI Act art. 12, 19, 26                | No notice period here: logs of high-risk systems must exist and be kept at least six months |                                              | Applies to Annex III systems from 2 December 2027 |

## Afterwards

Keep the archive, its digest and the report together; the archive verifies offline for as long
as you keep it. The recorder does not record your own response: the token change and the
export are not steps in any run. Keep the times from step 1 and step 2 in the incident ticket.
Give the agent the new token only when its host is clean.

## What the archive does not prove

- That the agent did nothing else. Only calls that went through the recorder are recorded; an
  attacker on the agent's host can call a model or a tool directly.
- That the export is complete. The manifest states the window you asked for; it cannot show
  that the recorder held no other run in it.
- That records after the last anchor are original, if the recorder's host was also taken.
- That what a model or a tool returned was true, or that a recorded step was right to take.
- That the incident is over.
