# BugBay — Local Pentest Lab Manager (Docker + hosts aliases)

Spin up a local playground of intentionally vulnerable web apps—**fast**, **repeatable**, and **safe** on loopback. BugBay manages Docker containers, friendly hostnames (via `/etc/hosts`), and a small set of Docker Compose labs, so you can focus on practicing and teaching web security—not yak-shaving.

---

## Why BugBay?

Modern appsec practice requires hands-on exploration. BugBay gives you a curated suite of classic targets (DVWA, bWAPP, Juice Shop, etc.) and one-liners to **start**, **stop**, **expose**, and **inspect** them—without memorizing container names or ports.

* 🧪 Purpose-built for **training, workshops, and self-study**
* 🐳 Works anywhere Docker works (Kali & most Linux distros)
* 🔐 Defaults to **loopback-only** with memorable hostnames (e.g., `http://dvwa`)
* 🧰 Extra power: LAN exposure (opt-in), logs tailing, shells, self-update
* 📦 Includes single-container labs and pointers to compose-based mega-labs

> Built and maintained by **HiddenInvestigations.Net** to make local pentest labs painless.

---

## Features

* **One command** to start a lab on loopback and add a hostname alias to `/etc/hosts`
* **Human-friendly commands**: `list · info · start · startpublic · status · stop · pull · logs · shell · rm · self-update`
* **Atomic & safe** `/etc/hosts` editing with file locking
* **Smarter port checks** that detect conflicts on `0.0.0.0`, IPv4, and IPv6
* **Compose wrapper** that supports both `docker compose` (v2) and `docker-compose` (legacy)
* **Clear, consistent UX** and helpful output

---

## Requirements

* Linux (Kali or most mainstream distros)
* Docker Engine
* Optional (for compose labs): `docker compose` **or** `docker-compose`
* Optional: `git` (for cloning compose lab repos)
* Optional: `curl` (for self-update)

> If your user is not in the `docker` group, BugBay will use `sudo` where needed.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/hidden-investigations/bugbay
cd bugbay

# Make the script executable
chmod +x bugbay.sh

# (Optional) Put it on your PATH
sudo ln -sf "$PWD/bugbay.sh" /usr/local/bin/bugbay
```

---

## Quick Start

```bash
# See what’s available
./bugbay.sh list

# Learn about a specific lab
./bugbay.sh info dvwa

# Start a lab on loopback + hostname alias (e.g., http://dvwa)
./bugbay.sh start dvwa

# Check which labs are running
./bugbay.sh status

# Stop a lab (and clean its hosts alias)
./bugbay.sh stop dvwa
```

**Loopback model:** each single-container lab binds to a distinct 127.x.y.z IP and maps its internal port to `80`, so `http://<labkey>` works in your browser without port numbers. Examples:

* `dvwa` → `127.8.0.1:80` → `http://dvwa`
* `juiceshop` → `127.10.0.1:80` → `http://juiceshop`

> Some services that expose secondary ports (e.g., MySQL for vulnerable WordPress) also map those to loopback.

---

## Usage

```bash
bugbay.sh {list|status|info|start|startpublic|stop|pull|logs|shell|rm|self-update} [lab] [args...]
```

### Common commands

* `list` — Show a table of labs (image/ports/type/notes)
* `info <lab>` — Detailed info (image, URLs, creds, notes)
* `status [all]` — Show running labs (or `all` to include stopped)
* `start <lab>` — Launch a lab on loopback + hostname alias
* `stop <lab>` — Stop a lab and clean hosts alias

### Power commands

* `startpublic <lab> [ip] [port]` — Expose a lab on your LAN
  *Example:* `./bugbay.sh startpublic dvwa 192.168.0.42 8080` → `http://192.168.0.42:8080`
* `pull <lab|all>` — Pull latest images
* `logs <lab>` — Tail container logs
* `shell <lab>` — Open an interactive shell inside the running container
* `rm <lab>` — Stop & remove containers; clean hosts
* `self-update` — Update the script from the repo’s published URL

> **Warning:** `startpublic` is for trusted networks/labs only. Know your environment before exposing intentionally vulnerable apps.

---

## Supported Labs (selection)

Single-container labs (loopback with hostname aliases):

| NAME                 | IMAGE                                   | DEFAULT PORTS          | NOTES                              |
|----------------------|-----------------------------------------|------------------------|------------------------------------|
| bwapp                | `raesene/bwapp`                         | `80`                   | PHP/MySQL vulns                    |
| webgoat7             | `webgoat/webgoat-7.1`                   | `8080`                 | OWASP training app                 |
| webgoat8             | `webgoat/webgoat-8.0`                   | `8080`                 | OWASP training app                 |
| webgoat81            | `webgoat/goatandwolf`                   | `8080`                 | WebWolf not mapped                 |
| dvwa                 | `vulnerables/web-dvwa`                  | `80`                   | Classic PHP target                 |
| mutillidae           | `citizenstig/nowasp`                    | `80`                   | OWASP Mutillidae II                |
| juiceshop            | `bkimminich/juice-shop`                 | `3000`                 | Modern JS app with vulns           |
| securityshepherd     | `ismisepaul/securityshepherd`           | `80`                   | OWASP training app                 |
| vulnerablewordpress  | `eystsen/vulnerablewordpress`           | `80` (`+3306` loopback)| WP + MySQL demo                    |
| securityninjas       | `opendns/security-ninjas`               | `80`                   | OpenDNS training app               |
| altoro               | `eystsen/altoro`                        | `8080`                 | Bank demo                          |
| graphql              | `carvesystems/vulnerable-graphql-api`   | `3000`                 | GraphQL vulns                      |
| railsgoat            | `owasp/railsgoat`                       | `3000`                 | Rails app                          |
| dvna                 | `appsecco/dvna`                         | `9090`                 | NodeJS app with OWASP Top 10       |
| nodegoat             | `vulnerables/web-owasp-nodegoat`        | `4000`                 | NodeGoat image variant             |
| brokencrystals       | `neuralegion/brokencrystals`            | `3000`                 | Modern full-stack                  |
| vulnerableapp        | `sasanlabs/owasp-vulnerableapp`         | `9090`                 | Java mega-lab                      |
| dvga                 | `dolevf/dvga`                           | `5013`                 | GraphQL vulnerabilities            |
| xvwa                 | `tuxotron/xvwa`                         | `80`                   | Classic PHP vuln app               |
| dvws                 | `tssoffsec/dvws`                        | `65412`                | WebSockets vulns                   |
| vampi                | `erev0s/vampi`                          | `5000`                 | REST API vulns                     |
| bodgeit              | `psiinon/bodgeit`                       | `8080`                 | Deprecated but useful              |
| wrongsecrets         | `jeroenwillemsen/wrongsecrets`          | `8080`                 | Secrets challenges                 |
| hackazon             | `pierrickv/hackazon`                    | `80`                   | E-commerce demo                    |
| crapi                | `owasp/crapi (compose)`                 | `8888` (`+8025`)       | Compose multi-service API lab      |
| vulhub               | `various (compose)`                     | `varies`               | CVE labs via compose               |

Compose labs (no `startpublic` helper; use compose):

* **crAPI (OWASP)** — `https://github.com/OWASP/crAPI`
* **Vulhub** — `https://github.com/vulhub/vulhub`

Use:

```bash
./bugbay.sh start crapi
./bugbay.sh stop crapi
```

> For Vulhub, BugBay prints pointers; choose a specific CVE lab and use `docker compose` in that directory.

---

## Networking & `/etc/hosts` model

* Starting a single-container lab:

  * Adds a line to `/etc/hosts` like `127.8.0.1 dvwa`
  * Runs the container with `-p 127.8.0.1:80:<container_port>`
* Stopping a lab:

  * Stops the container and removes the hostname entry

Edits are **atomic** and guarded with a file lock. On systems without `flock`, BugBay still writes atomically (best effort).

---

## Self-Update

`./bugbay.sh self-update` downloads the latest `bugbay.sh` from the repo’s raw URL, saves a timestamped backup, and swaps the file in place.

---

## Troubleshooting

* **“Docker is not running.”**
  BugBay will offer to start Docker via `systemctl`/`service`. You can also start it yourself:

  ```bash
  sudo systemctl start docker
  ```
* **Permission denied / cannot connect to the Docker daemon**
  You can add your user to the `docker` group or rely on BugBay’s `sudo` fallbacks:

  ```bash
  sudo usermod -aG docker "$USER"
  newgrp docker
  ```
* **Ports already in use**
  `startpublic` checks for collisions (e.g., `0.0.0.0:PORT` conflicts). Choose a different port/IP or stop the other process.
* **Images moved/removed**
  Docker Hub tags can drift. Use `pull` to refresh. If an image disappears upstream, switch to an alternative image or pin a known-good tag in your local fork.

---

## Security & Ethics

BugBay runs **intentionally vulnerable** apps. Use only in **controlled environments** you own or are authorized to test. Exposing labs (`startpublic`) can put you and others at risk—**don’t** expose to untrusted networks or the internet.

---

## Contributing

Contributions welcome! Common ideas:

* Add new labs or compose profiles
* Improve docs and examples
* Build small QA checks for `lab_db` correctness

Workflow:

1. Fork the repo
2. Create a feature branch
3. Keep changes focused and well-commented
4. Open a pull request with a clear description and test notes

---

## Project Info

* **Repository:** [https://github.com/hidden-investigations/bugbay](https://github.com/hidden-investigations/bugbay)
* **Website:** [https://HiddenInvestigations.Net](https://HiddenInvestigations.Net)

---

## License

This project is licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for details.

---

## Credits

* **Primary author & main contributor:** **[@sakibulalikhan](https://github.com/sakibulalikhan)**
* Maintained by **HiddenInvestigations.Net**

📬 Contact us: [hi@hiddeninvestigations.net](mailto:hi@hiddeninvestigations.net)

Community contributions and feedback are appreciated. If BugBay helped you run a class, workshop, or lab—tell us what worked and what you’d like to see next!