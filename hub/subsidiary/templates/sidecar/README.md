# The Atrium sidecar of the {{tool_id}} subsidiary

Atrium generated these files for the subsidiary `{{subsidiary_id}}` of the tool `{{tool_id}}`. The sidecar is the
team's office next to the tool: it thinks through Atrium's model gateway at {{atrium_url}} and works inside the tool
{{reach}}. It only connects out; it never listens on a port. None of these files holds a
secret: the sidecar creates its own key and receives its token when it enrolls.

| File | What it is |
| --- | --- |
| `config.json` | where Atrium and the tool are; mounted read-only |
| `docker-compose.yml` | the sidecar as its own container: non-root, read-only, no capabilities, no ports |
| `atrium-sidecar.service` | the sidecar as a systemd service with its own dynamic user |

**Run it as its own container or its own operating-system user, never as Atrium's account and never inside the
tool's own container.** It keeps its private key and token in its state directory (`/var/lib/atrium-sidecar`,
readable by that user only).

The image is the `sidecar` target of Atrium's own Dockerfile (`docker build --target sidecar -t atrium-sidecar .`
in an Atrium checkout); `docker-compose.yml` names it `{{image}}`. Without containers, `pip install .` in a checkout (no
extras) provides the `atrium-sidecar` command.

## First start: enrollment

An administrator issues an enrollment in Atrium (`POST /api/subsidiaries/{{tool_id}}/enrollment`). Atrium shows a
one-time code once; it is valid for 30 minutes and works once. Give it to the sidecar on its first start only:

With Docker (the code is passed through the environment of this one command and not written to any file):

```sh
ATRIUM_ENROLLMENT_CODE='<code>' docker compose up -d
```

The container joins the existing Docker network `{{network}}`, so it reaches the tool by its service name.

With systemd (the code lives in the service manager's memory until you unset it):

```sh
sudo install -D -m 0644 config.json /etc/atrium-sidecar/config.json
sudo install -m 0644 atrium-sidecar.service /etc/systemd/system/atrium-sidecar.service
sudo systemctl daemon-reload
sudo systemctl set-environment ATRIUM_ENROLLMENT_CODE='<code>'
sudo systemctl enable --now atrium-sidecar
sudo systemctl unset-environment ATRIUM_ENROLLMENT_CODE
```

After enrolling, the subsidiary is on probation in Atrium until the conformance checks pass and an administrator
approves its charter. If an attacker enrolled first with a leaked code, the real sidecar fails visibly: issue a new
enrollment in Atrium, which revokes the first one.

## Operating it

- `atrium-sidecar --config config.json --check` checks that Atrium and the bridge (or the tool's API) answer and runs
  the conformance vectors Atrium sends next; `--once` makes one pass of every task. Both exit when done.

- It exits with code 3 when its token was revoked or its owner disabled (enroll again), and with 4 when Atrium stopped
  the subsidiary. Neither is restarted automatically.
- While Atrium has the subsidiary paused it idles. Pausing, stopping and the kill switch are done in Atrium; the bridge
  refuses everything once the sidecar's last ticket expires (10 minutes by default), even if the sidecar keeps running.
