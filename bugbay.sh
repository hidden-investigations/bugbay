#!/usr/bin/env bash
#
# ██████  ██    ██  ██████  ██████   █████  ██    ██ 
# ██   ██ ██    ██ ██       ██   ██ ██   ██  ██  ██  
# ██████  ██    ██ ██   ███ ██████  ███████   ████   
# ██   ██ ██    ██ ██    ██ ██   ██ ██   ██    ██    
# ██████   ██████   ██████  ██████  ██   ██    ██ 
#
#               BugBay – by HiddenInvestigations.net
#
# Local Pentest Lab Manager (Docker + hosts aliases)
# Works on Kali and most Linux distros.
#

set -euo pipefail
IFS=$'\n\t'

BUGBAY_NAME="BugBay"
BUGBAY_BRAND="Hidden Investigations"
BUGBAY_BRAND_URL="HiddenInvestigations.net"
BUGBAY_UPDATE_URL="https://raw.githubusercontent.com/Hidden-Investigations/bugbay/main/bugbay.sh"

ETC_HOSTS="/etc/hosts"

############################################
# Colors / UI helpers
############################################
use_color=0
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  if [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then use_color=1; fi
fi
c()    { if [ "$use_color" -eq 1 ]; then printf "%s" "$(tput setaf "$1")$2$(tput sgr0)"; else printf "%s" "$2"; fi; }
bold() { if [ "$use_color" -eq 1 ]; then tput bold; fi; printf "%s" "$1"; if [ "$use_color" -eq 1 ]; then tput sgr0; fi; }
dim()  { if [ "$use_color" -eq 1 ]; then printf "%s" "$(tput dim)$1$(tput sgr0)"; else printf "%s" "$1"; fi; }

ascii_logo() {
cat <<EOF

██████  ██    ██  ██████  ██████   █████  ██    ██ 
██   ██ ██    ██ ██       ██   ██ ██   ██  ██  ██  
██████  ██    ██ ██   ███ ██████  ███████   ████   
██   ██ ██    ██ ██    ██ ██   ██ ██   ██    ██    
██████   ██████   ██████  ██████  ██   ██    ██ 

        ${BUGBAY_NAME} – by ${BUGBAY_BRAND_URL}
EOF
}

############################################
# Utils / Docker checks
############################################
_die() { echo "ERROR: $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

if have_cmd systemctl; then
  docker_status() { systemctl is-active docker >/dev/null 2>&1; }
  docker_start()  { sudo systemctl start docker; }
else
  docker_status() { sudo service docker status 2>/dev/null | grep -q "active (running)"; }
  docker_start()  { sudo service docker start; }
fi

# Safe wrapper for docker ps that never trips 'set -e'
dps() {
  sudo docker ps "$@" 2>/dev/null || true
}

ensure_docker_running() {
  if ! have_cmd docker; then
    _die "Docker not found. Install it (e.g. sudo apt install docker.io)"
  fi
  if ! docker_status; then
    echo "Docker is not running."
    printf "Start Docker now (y/n)? "
    read -r answer || true
    if printf '%s' "$answer" | grep -iq '^y'; then docker_start; else _die "Docker must be running for this command."; fi
  fi
}

############################################
# Port listening check (ss | netstat)
############################################
is_listening() { # ip port
  local ip="$1" port="$2"
  local listen="$ip:$port"
  if have_cmd ss; then
    ss -lnt4 2>/dev/null | awk '{print $4}' | grep -qx "$listen"
  elif have_cmd netstat; then
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qx "$listen"
  else
    return 1
  fi
}

############################################
# Help / Quick start
############################################
display_help() {
ascii_logo
cat <<EOF

$(bold "$BUGBAY_NAME – Local Pentest Lab Manager (Docker + hosts aliases)")
Brand: $BUGBAY_BRAND

Usage:
  $(bold "bugbay.sh {list|status|info|start|startpublic|stop|pull|logs|shell|rm|self-update} [project] [args...]")

Common:
  $(bold "list")                  Show a table of labs (image/ports/type/notes)
  $(bold "info <lab>")            Detailed info (image, URLs, creds, notes)
  $(bold "status [all]")          Show running labs (or all with 'all')
  $(bold "start <lab>")           Launch a lab on loopback + hosts alias
  $(bold "stop <lab>")            Stop a lab and clean hosts

Power:
  $(bold "startpublic <lab> [ip] [port]")  Expose a lab on your LAN  $(c 3 "WARNING")
  $(bold "pull <lab|all>")                 Pull latest images
  $(bold "logs <lab>")                     Tail container logs
  $(bold "shell <lab>")                    Shell inside a running container
  $(bold "rm <lab|all> [--images|--purge] [--yes|-y] [--dry-run]")  Safe cleanup
  $(bold "self-update")                    Update script from GitHub

Examples:
  ./bugbay.sh list
  ./bugbay.sh info dvwa
  ./bugbay.sh start dvwa
  ./bugbay.sh startpublic dvwa 192.168.0.42 8080
  ./bugbay.sh rm all --images --yes
  ./bugbay.sh logs juiceshop
  ./bugbay.sh pull all
  ./bugbay.sh shell bwapp

EOF
  exit 1
}

quick_start() {
  ascii_logo
  echo
  echo "$(bold "BugBay quick start")"
  echo "  $(bold "./bugbay.sh list")           – show labs (image/ports/type/notes)"
  echo "  $(bold "./bugbay.sh info dvwa")      – details for a lab (image, URLs, creds)"
  echo "  $(bold "./bugbay.sh start dvwa")     – start a lab locally"
  echo "  $(bold "./bugbay.sh status")         – show running labs"
  echo "  $(bold "./bugbay.sh startpublic dvwa 192.168.1.50 8080")  – expose on LAN $(c 3 "[danger]")"
  echo
  echo "Need more? $(bold "./bugbay.sh help")"
}

############################################
# /etc/hosts helpers — no /tmp usage
############################################
host_exists() { grep -qw "$1" "$ETC_HOSTS"; }

removehost() {
  local host="${1:?hostname required}"
  if host_exists "$host"; then
    echo "Removing $host from $ETC_HOSTS"
    sudo sh -c "awk -v h='$host' '{
      keep=1; for (i=2;i<=NF;i++) if (\$i==h) { keep=0; break }
      if (keep) print \$0
    }' '$ETC_HOSTS' > '${ETC_HOSTS}.bugbay.tmp' && mv '${ETC_HOSTS}.bugbay.tmp' '$ETC_HOSTS'"
  fi
}

addhost() {
  local ip="${1:?ip required}" host="${2:?host required}"
  if host_exists "$host"; then
    echo "$host already exists in $ETC_HOSTS"
    return 0
  fi
  echo "Adding $host to $ETC_HOSTS"
  sudo sh -c "printf '%s\t%s\n' '$ip' '$host' >> '$ETC_HOSTS'"
  if host_exists "$host"; then
    echo "$ip	$host was added successfully to $ETC_HOSTS"
  else
    _die "Failed to add $host"
  fi
}

############################################
# Registry (for list/info & rm --images)
# key|Name|Type|Image|DefaultPorts|LoopbackIP|URLHint|ShortNote|Creds
############################################
lab_db() {
cat <<'DB'
bwapp|bWAPP|single|raesene/bwapp|80|127.5.0.1|http://bwapp|PHP/MySQL vulns|bee/bug (after install)
webgoat7|WebGoat 7.1|single|webgoat/webgoat-7.1|8080|127.6.0.1|http://webgoat7/WebGoat|OWASP training app|
webgoat8|WebGoat 8.0|single|webgoat/webgoat-8.0|8080|127.7.0.1|http://webgoat8/WebGoat|OWASP training app|
webgoat81|WebGoat 8.1|single|webgoat/goatandwolf|8080|127.17.0.1|http://webgoat81/WebGoat|WebWolf not mapped|
dvwa|DVWA|single|vulnerables/web-dvwa|80|127.8.0.1|http://dvwa|Classic PHP target|admin/password (create DB)
mutillidae|Mutillidae II|single|citizenstig/nowasp|80|127.9.0.1|http://mutillidae|OWASP Mutillidae II|
juiceshop|OWASP Juice Shop|single|bkimminich/juice-shop|3000|127.10.0.1|http://juiceshop|Modern JS app with vulns|
vulnerablewordpress|Vuln WordPress|single|eystsen/vulnerablewordpress|80 (+3306 loopback)|127.12.0.1|http://vulnerablewordpress|WP+MySQL demo|
securityninjas|Security Ninjas|single|opendns/security-ninjas|80|127.13.0.1|http://securityninjas|OpenDNS training app|
altoro|Altoro Mutual|single|eystsen/altoro|8080|127.14.0.1|http://altoro|Bank demo|jsmith/demo1234; admin/admin
graphql|Vulnerable GraphQL API|single|carvesystems/vulnerable-graphql-api|3000→80|127.15.0.1|http://graphql|GraphQL vulns|
railsgoat|RailsGoat|single|owasp/railsgoat|3000|127.18.0.1|http://railsgoat:3000|Rails app|
dvna|DVNA|single|appsecco/dvna|9090|127.19.0.1|http://dvna:9090|NodeJS app with OWASP Top 10|
nodegoat|NodeGoat (image)|single|vulnerables/web-owasp-nodegoat|4000|127.20.0.1|http://nodegoat:4000|NodeGoat image variant|
brokencrystals|BrokenCrystals|single|neuralegion/brokencrystals|3000|127.21.0.1|http://brokencrystals:3000|Modern full-stack|
vulnerableapp|OWASP VulnerableApp|single|sasanlabs/owasp-vulnerableapp|9090|127.22.0.1|http://vulnerableapp:9090|Java mega-lab|
dvga|DVGA (GraphQL)|single|dolevf/dvga|5013|127.23.0.1|http://dvga:5013|GraphQL vulnerabilities|
xvwa|XVWA|single|tuxotron/xvwa|80|127.24.0.1|http://xvwa|Classic PHP vuln app|
dvws|DVWS|single|tssoffsec/dvws|65412|127.25.0.1|http://dvws:65412|WebSockets vulns|
vampi|VAmPI|single|erev0s/vampi|5000|127.26.0.1|http://vampi:5000|REST API vulns|set env vulnerable=1
bodgeit|BodgeIt Store|single|psiinon/bodgeit|8080|127.27.0.1|http://bodgeit:8080|Deprecated but useful|
wrongsecrets|OWASP WrongSecrets|single|jeroenwillemsen/wrongsecrets|8080|127.28.0.1|http://wrongsecrets:8080|Secrets challenges|
hackazon|Hackazon|single|pierrickv/hackazon|80|127.29.0.1|http://hackazon|E-commerce demo|
crapi|OWASP crAPI|compose|owasp/crAPI (compose)|8888 (+8025)|N/A|http://localhost:8888|Compose multi-service API lab|
vulhub|Vulhub|compose|various (compose)|varies|N/A|https://github.com/vulhub/vulhub|CVE labs via compose|
DB
}

# helpers to query lab_db
lab_field() { # usage: lab_field <key> <idx>
  local k="$1" idx="$2"
  lab_db | awk -F'|' -v k="$k" -v i="$idx" '$1==k{print $i; exit}'
}
lab_type()  { lab_field "$1" 3; }
lab_image() { lab_field "$1" 4; }
single_keys() { lab_db | awk -F'|' '$3=="single"{print $1}'; }

############################################
# Info / List output
############################################
print_info() {
  local key="${1:?info needs <lab>}"
  local line
  line="$(lab_db | awk -F'|' -v k="$key" '$1==k{print $0}')"
  [ -z "$line" ] && _die "Unknown lab: $key"
  IFS='|' read -r _ name type image ports ip url note creds <<<"$line"
  ascii_logo; echo
  echo "$(bold "$name")"
  printf "%-12s %s\n" "Key:" "$key"
  printf "%-12s %s\n" "Type:" "$type"
  printf "%-12s %s\n" "Image:" "$image"
  printf "%-12s %s\n" "Default:" "$ports"
  printf "%-12s %s\n" "Loopback:" "$ip"
  printf "%-12s %s\n" "URL hint:" "$url"
  printf "%-12s %s\n" "Notes:" "${note:-—}"
  printf "%-12s %s\n" "Creds:" "${creds:-—}"
  echo
  if [ "$type" = "compose" ]; then
    echo "Start: $(bold "./bugbay.sh start $key")   •   Stop: $(bold "./bugbay.sh stop $key")"
    echo "Public: edit compose to publish ports (not supported via startpublic)."
  else
    echo "Start: $(bold "./bugbay.sh start $key")   •   Stop: $(bold "./bugbay.sh stop $key")   •   Public: $(bold "./bugbay.sh startpublic $key <ip> [port]")"
  fi
}

list() {
  ascii_logo; echo
  echo "$(bold "Available labs") — $(dim "use: ./bugbay.sh info <lab>")"
  printf "%-18s  %-6s  %-28s  %-18s  %s\n" "$(bold NAME)" "$(bold TYPE)" "$(bold IMAGE)" "$(bold DEFAULT PORTS)" "$(bold NOTES)"
  printf "%-18s  %-6s  %-28s  %-18s  %s\n" "------------------" "------" "----------------------------" "------------------" "-------------------------------"
  lab_db | while IFS='|' read -r key name type image ports ip url note creds; do
    printf "%-18s  %-6s  %-28s  %-18s  %s\n" "$key" "$type" "$image" "$ports" "$note"
  done
  echo; echo "Example:  $(bold "./bugbay.sh info dvwa")"
}

############################################
# Docker helpers
############################################
project_start() {
  ensure_docker_running
  local fullname="$1" projectname="$2" image="$3" ip="$4" port="$5"
  local port2="${6-}" extra="${7-}"
  echo "Starting $fullname"
  addhost "$ip" "$projectname"
  local existing; existing="$(dps -aq -f "name=^/${projectname}$")"
  if [ -n "$existing" ]; then
    echo "docker start $projectname"
    sudo docker start "$projectname" >/dev/null
  else
    if [ -n "$port2" ]; then
      echo "docker run --name $projectname -d -p $ip:80:$port -p $ip:$port2:$port2 $extra $image"
      # shellcheck disable=SC2086
      sudo docker run --name "$projectname" -d -p "$ip:80:$port" -p "$ip:$port2:$port2" $extra "$image" >/dev/null
    else
      echo "docker run --name $projectname -d -p $ip:80:$port $extra $image"
      # shellcheck disable=SC2086
      sudo docker run --name "$projectname" -d -p "$ip:80:$port" $extra "$image" >/dev/null
    fi
  fi
  echo "$(c 2 "DONE")  http://$projectname   or   http://$ip"
}

project_startpublic() {
  ensure_docker_running
  local fullname="$1" projectname="${2}public" image="$3" internalport="$4" publicip="$5" port="$6" extra="${7-}"
  echo "Starting $fullname (public)"
  local existing; existing="$(dps -aq -f "name=^/${projectname}$")"
  if [ -n "$existing" ]; then
    echo "docker start $projectname"
    sudo docker start "$projectname" >/dev/null
  else
    echo "docker run --name $projectname -d -p $publicip:$port:$internalport $extra $image"
    # shellcheck disable=SC2086
    sudo docker run --name "$projectname" -d -p "$publicip:$port:$internalport" $extra "$image" >/dev/null
  fi
  if [ "$port" -eq 80 ]; then echo "$(c 1 "PUBLIC")  http://$publicip"; else echo "$(c 1 "PUBLIC")  http://$publicip:$port"; fi
}

project_stop() {
  ensure_docker_running
  local fullname="$1" projectname="$2"
  local cid; cid="$(dps -q -f "name=^/${projectname}$")"
  if [ -n "$cid" ]; then
    echo "Stopping $fullname (local)"; sudo docker stop "$projectname" >/dev/null; removehost "$projectname"
  fi
  local public="${projectname}public"
  cid="$(dps -q -f "name=^/${public}$")"
  [ -n "$cid" ] && { echo "Stopping $fullname (public)"; sudo docker stop "$public" >/dev/null; }
}

############################################
# Status (flat, prints rows, robust)
############################################
project_status() {
  ensure_docker_running
  local mode="${1:-running}"

  printf "%-28s  %-7s  %s\n" "$(bold Application)" "$(bold State)" "$(bold Info)"
  printf "%-28s  %-7s  %s\n" "----------------------------" "-------" "-----------------------------"

  local total=0 running=0 public=0

  while IFS='|' read -r title short url; do
    [ -z "$short" ] && continue
    total=$((total+1))

    local cid_local cid_pub
    cid_local="$(dps -q -f "name=^/${short}$")"
    cid_pub="$(dps -q -f "name=^/${short}public$")"

    if [ -n "$cid_local" ] || [ -n "$cid_pub" ]; then
      if [ -n "$cid_local" ]; then
        printf "%-28s  %s  %s\n" "$title" "$(c 2 RUNNING)" "$(dim "$url")"
        running=$((running+1))
      fi
      if [ -n "$cid_pub" ]; then
        printf "%-28s  %s\n" "$title" "$(c 1 PUBLIC)"
        public=$((public+1))
      fi
    elif [ "$mode" = "all" ]; then
      printf "%-28s  %s\n" "$title" "$(dim stopped)"
    fi
  done <<'TABLE'
bWAPP|bwapp|http://bwapp
WebGoat 7.1|webgoat7|http://webgoat7/WebGoat
WebGoat 8.0|webgoat8|http://webgoat8/WebGoat
WebGoat 8.1|webgoat81|http://webgoat81/WebGoat
DVWA|dvwa|http://dvwa
Mutillidae II|mutillidae|http://mutillidae
OWASP Juice Shop|juiceshop|http://juiceshop
Vuln WordPress|vulnerablewordpress|http://vulnerablewordpress
Security Ninjas|securityninjas|http://securityninjas
Altoro Mutual|altoro|http://altoro
Vulnerable GraphQL|graphql|http://graphql
RailsGoat|railsgoat|http://railsgoat:3000
DVNA|dvna|http://dvna:9090
NodeGoat (image)|nodegoat|http://nodegoat:4000
BrokenCrystals|brokencrystals|http://brokencrystals:3000
VulnerableApp|vulnerableapp|http://vulnerableapp:9090
DVGA (GraphQL)|dvga|http://dvga:5013
XVWA|xvwa|http://xvwa
DVWS|dvws|http://dvws:65412
VAmPI|vampi|http://vampi:5000
BodgeIt|bodgeit|http://bodgeit:8080
WrongSecrets|wrongsecrets|http://wrongsecrets:8080
Hackazon|hackazon|http://hackazon
TABLE

  echo
  printf "Apps: %s, Local running: %s, Public running: %s\n" "$total" "$running" "$public"
  echo "$(dim "Compose labs: crAPI, Vulhub (use docker compose)")"
}

############################################
# Remove (containers/hosts [+ optional images])
############################################
remove_container_if_exists() { # name
  local n="$1"
  if [ -n "$(sudo docker ps -a -q -f "name=^/${n}$" 2>/dev/null || true)" ]; then
    echo "Removing container: $n"
    sudo docker rm -f -v "$n" >/dev/null || true
  fi
}

remove_image_if_exists() { # repo (we only remove repo:latest)
  local repo="$1"
  local ref="${repo}:latest"
  local iid
  iid="$(sudo docker images -q "$ref" 2>/dev/null || true)"
  if [ -n "$iid" ]; then
    echo "Removing image: $ref"
    sudo docker rmi -f "$ref" >/dev/null || true
  fi
}

project_rm_one() { # key do_images dry_run
  ensure_docker_running
  local key="$1" do_images="$2" dry="$3"
  local type image
  type="$(lab_type "$key" || true)"
  [ -z "$type" ] && { echo "Skipping unknown lab: $key"; return; }
  if [ "$type" != "single" ]; then
    echo "Skipping compose lab (use compose directly): $key"
    return
  fi
  image="$(lab_image "$key")"
  echo "Cleaning lab: $key"

  if [ "$dry" = "1" ]; then
    echo "  would stop   : $key (local)"
    echo "  would stop   : ${key}public (public)"
    echo "  would rm cont: $key"
    echo "  would rm cont: ${key}public"
    echo "  would unhost : $key"
    if [ "$do_images" = "1" ]; then
      echo "  would rmi    : ${image}:latest"
    fi
    return
  fi

  # stop if running (prints stops)
  project_stop "$key" "$key" || true
  # remove local/public containers
  remove_container_if_exists "$key"
  remove_container_if_exists "${key}public"
  # clean hosts
  removehost "$key" || true
  # optional images (only repo:latest)
  if [ "$do_images" = "1" ]; then
    remove_image_if_exists "$image"
  fi
  echo "Done: $key"
}

rm_dispatch() {
  ensure_docker_running
  local target="${1-}"; shift || true

  # flags
  local DO_IMAGES=0 ASSUME_YES=0 DRY_RUN=0
  while [ "${1-}" != "" ]; do
    case "$1" in
      --images|--purge) DO_IMAGES=1 ;;
      --yes|-y)         ASSUME_YES=1 ;;
      --dry-run)        DRY_RUN=1 ;;
      *) _die "Unknown flag for rm: $1" ;;
    esac
    shift || true
  done

  if [ -z "$target" ]; then _die "rm needs <lab|all> [--images|--purge] [--yes|-y] [--dry-run]"; fi

  if [ "$target" = "all" ]; then
    if [ "$DRY_RUN" = "0" ] && [ "$ASSUME_YES" = "0" ]; then
      echo "This will remove all single-container lab containers and hosts${DO_IMAGES:+, and images (:latest)}."
      printf "Proceed (y/N)? "
      read -r ans || true
      if ! printf '%s' "$ans" | grep -iq '^y'; then
        echo "Aborted."; return
      fi
    fi
    echo "Cleaning all single-container labs${DO_IMAGES:+ (including images)}..."
    while read -r k; do project_rm_one "$k" "$DO_IMAGES" "$DRY_RUN"; done < <(single_keys)
    echo "All single-container labs processed."
    echo "Note: compose labs (crAPI, Vulhub) are not removed by 'rm all'."
    return
  fi

  # single lab
  local type; type="$(lab_type "$target" || true)"
  [ -z "$type" ] && _die "Unknown lab: $target"
  if [ "$DRY_RUN" = "0" ] && [ "$ASSUME_YES" = "0" ] && [ "$DO_IMAGES" = "1" ]; then
    echo "This will remove containers/hosts and the image (:latest) for '$target'."
    printf "Proceed (y/N)? "
    read -r ans || true
    if ! printf '%s' "$ans" | grep -iq '^y'; then
      echo "Aborted."; return
    fi
  fi
  project_rm_one "$target" "$DO_IMAGES" "$DRY_RUN"
}

############################################
# Compose helpers (with fallbacks)
############################################
_have_compose() {
  if have_cmd docker && docker compose version >/dev/null 2>&1; then
    echo "docker-compose-v2"
    return 0
  elif have_cmd docker-compose; then
    echo "docker-compose-v1"
    return 0
  fi
  return 1
}

compose_cmd() {
  if [ "$(_have_compose || true)" = "docker-compose-v1" ]; then
    echo "docker-compose"
  else
    echo "docker compose"
  fi
}

compose_start() {
  ensure_docker_running
  have_cmd git || _die "git is required to clone compose repos"
  local name="$1" git_url="$2" compose_dir="$3" hint="$4"
  _have_compose || _die "docker compose (or docker-compose) is required"
  local DCMD; DCMD="$(compose_cmd)"
  echo "Starting $name via $DCMD ..."
  mkdir -p "$HOME/.bugbay"
  if [ ! -d "$HOME/.bugbay/$name" ]; then git clone "$git_url" "$HOME/.bugbay/$name"; fi
  ( cd "$HOME/.bugbay/$name/$compose_dir" && $DCMD pull && $DCMD up -d )
  echo "$name started. Try: $hint"
}
compose_stop() {
  ensure_docker_running
  _have_compose || _die "docker compose (or docker-compose) is required"
  local DCMD; DCMD="$(compose_cmd)"
  local name="$1" compose_dir="$2"
  if [ -d "$HOME/.bugbay/$name/$compose_dir" ]; then
    ( cd "$HOME/.bugbay/$name/$compose_dir" && $DCMD down )
  else
    echo "Compose dir for $name not found."
  fi
}
compose_info() { echo "$1 uses multiple compose labs. Browse: $2"; }

############################################
# Extra ops
############################################
pull_image() { ensure_docker_running; echo "Pulling $1 ..."; sudo docker pull "$1" || true; }
pull_dispatch() {
  local target="${1-}"; [ -z "$target" ] && _die "pull needs <lab|all>"
  if [ "$target" = "all" ]; then
    for img in \
      raesene/bwapp webgoat/webgoat-7.1 webgoat/webgoat-8.0 webgoat/goatandwolf \
      vulnerables/web-dvwa citizenstig/nowasp bkimminich/juice-shop \
      eystsen/vulnerablewordpress opendns/security-ninjas eystsen/altoro \
      carvesystems/vulnerable-graphql-api owasp/railsgoat appsecco/dvna \
      vulnerables/web-owasp-nodegoat neuralegion/brokencrystals \
      sasanlabs/owasp-vulnerableapp dolevf/dvga tuxotron/xvwa tssoffsec/dvws \
      erev0s/vampi psiinon/bodgeit jeroenwillemsen/wrongsecrets \
      pierrickv/hackazon
    do pull_image "$img"; done
    echo "Note: compose labs (crAPI, Vulhub) not pulled by 'pull all'."
  else
    case "$target" in
      bwapp) pull_image "raesene/bwapp" ;;
      webgoat7) pull_image "webgoat/webgoat-7.1" ;;
      webgoat8) pull_image "webgoat/webgoat-8.0" ;;
      webgoat81) pull_image "webgoat/goatandwolf" ;;
      dvwa) pull_image "vulnerables/web-dvwa" ;;
      mutillidae) pull_image "citizenstig/nowasp" ;;
      juiceshop) pull_image "bkimminich/juice-shop" ;;
      vulnerablewordpress) pull_image "eystsen/vulnerablewordpress" ;;
      securityninjas) pull_image "opendns/security-ninjas" ;;
      altoro) pull_image "eystsen/altoro" ;;
      graphql) pull_image "carvesystems/vulnerable-graphql-api" ;;
      railsgoat) pull_image "owasp/railsgoat" ;;
      dvna) pull_image "appsecco/dvna" ;;
      nodegoat) pull_image "vulnerables/web-owasp-nodegoat" ;;
      brokencrystals) pull_image "neuralegion/brokencrystals" ;;
      vulnerableapp) pull_image "sasanlabs/owasp-vulnerableapp" ;;
      dvga) pull_image "dolevf/dvga" ;;
      xvwa) pull_image "tuxotron/xvwa" ;;
      dvws) pull_image "tssoffsec/dvws" ;;
      vampi) pull_image "erev0s/vampi" ;;
      bodgeit) pull_image "psiinon/bodgeit" ;;
      wrongsecrets) pull_image "jeroenwillemsen/wrongsecrets" ;;
      hackazon) pull_image "pierrickv/hackazon" ;;
      crapi|vulhub) echo "Use compose directories to pull these." ;;
      *) _die "Unknown lab: $target" ;;
    esac
  fi
}
logs_dispatch() {
  ensure_docker_running
  local app="${1-}"; [ -z "$app" ] && _die "logs needs <lab>"
  local name="$app"
  if [ -z "$(sudo docker ps -a -q -f "name=^/${name}$" 2>/dev/null || true)" ]; then
    if [ -n "$(sudo docker ps -a -q -f "name=^/${name}public$" 2>/dev/null || true)" ]; then name="${name}public"; else _die "No container found: $app"; fi
  fi
  sudo docker logs -f "$name"
}
shell_dispatch() {
  ensure_docker_running
  local app="${1-}"; [ -z "$app" ] && _die "shell needs <lab>"
  local name="$app"
  if [ -z "$(dps -q -f "name=^/${name}$")" ]; then
    if [ -n "$(dps -q -f "name=^/${name}public$")" ]; then name="${name}public"; else _die "Container not running: $app"; fi
  fi
  if sudo docker exec "$name" bash -lc 'true' 2>/dev/null; then sudo docker exec -it "$name" bash; else sudo docker exec -it "$name" sh; fi
}
self_update() {
  echo "Downloading: $BUGBAY_UPDATE_URL"
  local tmp; tmp="$(mktemp)"
  if have_cmd curl && curl -fsSL "$BUGBAY_UPDATE_URL" -o "$tmp"; then
    :
  elif have_cmd wget && wget -qO "$tmp" "$BUGBAY_UPDATE_URL"; then
    :
  else
    rm -f "$tmp" || true; _die "Neither curl nor wget available to self-update."
  fi
  chmod +x "$tmp"
  cp "$0" "${0}.bak.$(date +%s)"
  mv "$tmp" "$0"
  echo "Updated. Backup saved as ${0}.bak.<timestamp>"
}

############################################
# Dispatchers
############################################
project_start_dispatch() {
  case "$1" in
    bwapp)               project_start "bWAPP" "bwapp" "raesene/bwapp" "127.5.0.1" "80" ;;
    webgoat7)            project_start "WebGoat 7.1" "webgoat7" "webgoat/webgoat-7.1" "127.6.0.1" "8080" ;;
    webgoat8)            project_start "WebGoat 8.0" "webgoat8" "webgoat/webgoat-8.0" "127.7.0.1" "8080" ;;
    webgoat81)           project_start "WebGoat 8.1" "webgoat81" "webgoat/goatandwolf" "127.17.0.1" "8080" ;;
    dvwa)                project_start "DVWA" "dvwa" "vulnerables/web-dvwa" "127.8.0.1" "80" ;;
    mutillidae)          project_start "Mutillidae II" "mutillidae" "citizenstig/nowasp" "127.9.0.1" "80" ;;
    juiceshop)           project_start "OWASP Juice Shop" "juiceshop" "bkimminich/juice-shop" "127.10.0.1" "3000" ;;
    securitysheperd|securityshepherd)
                         project_start "OWASP Security Shepherd" "securitysheperd" "ismisepaul/securityshepherd" "127.11.0.1" "80" ;;
    vulnerablewordpress) project_start "Vuln WordPress" "vulnerablewordpress" "eystsen/vulnerablewordpress" "127.12.0.1" "80" "3306" ;;
    securityninjas)      project_start "OpenDNS Security Ninjas" "securityninjas" "opendns/security-ninjas" "127.13.0.1" "80" ;;
    altoro)              project_start "Altoro Mutual" "altoro" "eystsen/altoro" "127.14.0.1" "8080" ;;
    graphql)             project_start "Vulnerable GraphQL API" "graphql" "carvesystems/vulnerable-graphql-api" "127.15.0.1" "3000" ;;
    railsgoat)           project_start "RailsGoat" "railsgoat" "owasp/railsgoat" "127.18.0.1" "3000" ;;
    dvna)                project_start "DVNA" "dvna" "appsecco/dvna" "127.19.0.1" "9090" ;;
    nodegoat)            project_start "NodeGoat (image)" "nodegoat" "vulnerables/web-owasp-nodegoat" "127.20.0.1" "4000" ;;
    brokencrystals)      project_start "BrokenCrystals" "brokencrystals" "neuralegion/brokencrystals" "127.21.0.1" "3000" ;;
    vulnerableapp)       project_start "OWASP VulnerableApp" "vulnerableapp" "sasanlabs/owasp-vulnerableapp" "127.22.0.1" "9090" ;;
    dvga)                project_start "DVGA (GraphQL)" "dvga" "dolevf/dvga" "127.23.0.1" "5013" ;;
    xvwa)                project_start "XVWA" "xvwa" "tuxotron/xvwa" "127.24.0.1" "80" ;;
    dvws)                project_start "DVWS" "dvws" "tssoffsec/dvws" "127.25.0.1" "65412" ;;
    vampi)               project_start "VAmPI" "vampi" "erev0s/vampi" "127.26.0.1" "5000" "" "-e vulnerable=1" ;;
    bodgeit)             project_start "BodgeIt Store" "bodgeit" "psiinon/bodgeit" "127.27.0.1" "8080" ;;
    wrongsecrets)        project_start "OWASP WrongSecrets" "wrongsecrets" "jeroenwillemsen/wrongsecrets" "127.28.0.1" "8080" ;;
    hackazon)            project_start "Hackazon" "hackazon" "pierrickv/hackazon" "127.29.0.1" "80" ;;
    crapi)               compose_start "crAPI" "https://github.com/OWASP/crAPI" "deploy/docker" "http://localhost:8888" ;;
    vulhub)              compose_info "vulhub" "https://github.com/vulhub/vulhub" ;;
    *) _die "Unknown lab: $1" ;;
  esac
}

project_startpublic_dispatch() {
  local publicip="$2" port="$3"
  case "$1" in
    bwapp)          project_startpublic "bWAPP" "bwapp" "raesene/bwapp" "80" "$publicip" "$port" ;;
    webgoat7)       project_startpublic "WebGoat 7.1" "webgoat7" "webgoat/webgoat-7.1" "8080" "$publicip" "$port" ;;
    webgoat8)       project_startpublic "WebGoat 8.0" "webgoat8" "webgoat/webgoat-8.0" "8080" "$publicip" "$port" ;;
    webgoat81)      project_startpublic "WebGoat 8.1" "webgoat81" "webgoat/goatandwolf" "8080" "$publicip" "$port" ;;
    dvwa)           project_startpublic "DVWA" "dvwa" "vulnerables/web-dvwa" "80" "$publicip" "$port" ;;
    mutillidae)     project_startpublic "Mutillidae II" "mutillidae" "citizenstig/nowasp" "80" "$publicip" "$port" ;;
    juiceshop)      project_startpublic "OWASP Juice Shop" "juiceshop" "bkimminich/juice-shop" "3000" "$publicip" "$port" ;;
    securitysheperd|securityshepherd)
                    project_startpublic "Security Shepherd" "securitysheperd" "ismisepaul/securityshepherd" "80" "$publicip" "$port" ;;
    vulnerablewordpress)
                    project_startpublic "Vuln WordPress" "vulnerablewordpress" "eystsen/vulnerablewordpress" "80" "$publicip" "$port" ;;
    securityninjas) project_startpublic "Security Ninjas" "securityninjas" "opendns/security-ninjas" "80" "$publicip" "$port" ;;
    altoro)         project_startpublic "Altoro Mutual" "altoro" "eystsen/altoro" "8080" "$publicip" "$port" ;;
    graphql)        project_startpublic "Vulnerable GraphQL" "graphql" "carvesystems/vulnerable-graphql-api" "3000" "$publicip" "$port" ;;
    railsgoat)      project_startpublic "RailsGoat" "railsgoat" "owasp/railsgoat" "3000" "$publicip" "$port" ;;
    dvna)           project_startpublic "DVNA" "dvna" "appsecco/dvna" "9090" "$publicip" "$port" ;;
    nodegoat)       project_startpublic "NodeGoat" "nodegoat" "vulnerables/web-owasp-nodegoat" "4000" "$publicip" "$port" ;;
    brokencrystals) project_startpublic "BrokenCrystals" "brokencrystals" "neuralegion/brokencrystals" "3000" "$publicip" "$port" ;;
    vulnerableapp)  project_startpublic "VulnerableApp" "vulnerableapp" "sasanlabs/owasp-vulnerableapp" "9090" "$publicip" "$port" ;;
    dvga)           project_startpublic "DVGA" "dvga" "dolevf/dvga" "5013" "$publicip" "$port" ;;
    xvwa)           project_startpublic "XVWA" "xvwa" "tuxotron/xvwa" "80" "$publicip" "$port" ;;
    dvws)           project_startpublic "DVWS" "dvws" "tssoffsec/dvws" "65412" "$publicip" "$port" ;;
    vampi)          project_startpublic "VAmPI" "vampi" "erev0s/vampi" "5000" "$publicip" "$port" "-e vulnerable=1" ;;
    bodgeit)        project_startpublic "BodgeIt" "bodgeit" "psiinon/bodgeit" "8080" "$publicip" "$port" ;;
    wrongsecrets)   project_startpublic "WrongSecrets" "wrongsecrets" "jeroenwillemsen/wrongsecrets" "8080" "$publicip" "$port" ;;
    hackazon)       project_startpublic "Hackazon" "hackazon" "pierrickv/hackazon" "80" "$publicip" "$port" ;;
    crapi|vulhub)   echo "Public mode not supported for compose labs ($1) – adjust compose."; ;;
    *) _die "Unknown lab: $1" ;;
  esac
}

project_stop_dispatch() {
  case "$1" in
    bwapp|webgoat7|webgoat8|webgoat81|dvwa|mutillidae|juiceshop|vulnerablewordpress|securityninjas|altoro|graphql|railsgoat|dvna|nodegoat|brokencrystals|vulnerableapp|dvga|xvwa|dvws|vampi|bodgeit|wrongsecrets|hackazon)
      project_stop "$1" "$1" ;;
    crapi) compose_stop "crAPI" "deploy/docker" ;;
    vulhub) echo "Vulhub: run docker compose down in the chosen lab dir." ;;
    *) _die "Unknown lab: $1" ;;
  esac
}

############################################
# Extra ops
############################################
pull_dispatch() { # unchanged from earlier version
  local target="${1-}"; [ -z "$target" ] && _die "pull needs <lab|all>"
  if [ "$target" = "all" ]; then
    for img in \
      raesene/bwapp webgoat/webgoat-7.1 webgoat/webgoat-8.0 webgoat/goatandwolf \
      vulnerables/web-dvwa citizenstig/nowasp bkimminich/juice-shop \
      eystsen/vulnerablewordpress opendns/security-ninjas eystsen/altoro \
      carvesystems/vulnerable-graphql-api owasp/railsgoat appsecco/dvna \
      vulnerables/web-owasp-nodegoat neuralegion/brokencrystals \
      sasanlabs/owasp-vulnerableapp dolevf/dvga tuxotron/xvwa tssoffsec/dvws \
      erev0s/vampi psiinon/bodgeit jeroenwillemsen/wrongsecrets \
      pierrickv/hackazon
    do pull_image "$img"; done
    echo "Note: compose labs (crAPI, Vulhub) not pulled by 'pull all'."
  else
    case "$target" in
      bwapp) pull_image "raesene/bwapp" ;;
      webgoat7) pull_image "webgoat/webgoat-7.1" ;;
      webgoat8) pull_image "webgoat/webgoat-8.0" ;;
      webgoat81) pull_image "webgoat/goatandwolf" ;;
      dvwa) pull_image "vulnerables/web-dvwa" ;;
      mutillidae) pull_image "citizenstig/nowasp" ;;
      juiceshop) pull_image "bkimminich/juice-shop" ;;
      vulnerablewordpress) pull_image "eystsen/vulnerablewordpress" ;;
      securityninjas) pull_image "opendns/security-ninjas" ;;
      altoro) pull_image "eystsen/altoro" ;;
      graphql) pull_image "carvesystems/vulnerable-graphql-api" ;;
      railsgoat) pull_image "owasp/railsgoat" ;;
      dvna) pull_image "appsecco/dvna" ;;
      nodegoat) pull_image "vulnerables/web-owasp-nodegoat" ;;
      brokencrystals) pull_image "neuralegion/brokencrystals" ;;
      vulnerableapp) pull_image "sasanlabs/owasp-vulnerableapp" ;;
      dvga) pull_image "dolevf/dvga" ;;
      xvwa) pull_image "tuxotron/xvwa" ;;
      dvws) pull_image "tssoffsec/dvws" ;;
      vampi) pull_image "erev0s/vampi" ;;
      bodgeit) pull_image "psiinon/bodgeit" ;;
      wrongsecrets) pull_image "jeroenwillemsen/wrongsecrets" ;;
      hackazon) pull_image "pierrickv/hackazon" ;;
      crapi|vulhub) echo "Use compose directories to pull these." ;;
      *) _die "Unknown lab: $target" ;;
    esac
  fi
}

############################################
# Main
############################################
case "${1-}" in
  help|-h|--help) display_help ;;
  "")             quick_start ;;
  list)           list ;;
  info)           [ -z "${2-}" ] && { echo "usage: $0 info <lab>"; exit 1; }; print_info "$2" ;;
  status)         if [ "${2-}" = "all" ]; then project_status "all"; else project_status "running"; fi ;;
  start)          [ -z "${2-}" ] && { echo "usage: $0 start <lab>"; exit 1; }; project_start_dispatch "$2" ;;
  startpublic)    [ -z "${2-}" ] && { echo "usage: $0 startpublic <lab> [ip] [port]"; exit 1; }
                  port="${4-80}"
                  if [ -n "${3-}" ]; then publicip="$3"; else publicip=$(hostname -I | awk '{print $1}'); fi
                  if is_listening "$publicip" "$port"; then _die "$publicip already listening on $port"; fi
                  project_startpublic_dispatch "$2" "$publicip" "$port"
                  echo "$(c 3 "WARNING") expose only in trusted labs." ;;
  stop)           [ -z "${2-}" ] && { echo "usage: $0 stop <lab>"; exit 1; }; project_stop_dispatch "$2" ;;
  rm)             shift; rm_dispatch "${1-}" ${2:+$2} ${3:+$3} ;;
  logs)           logs_dispatch "${2-}" ;;
  shell)          shell_dispatch "${2-}" ;;
  pull)           pull_dispatch "${2-}" ;;
  self-update|selfupdate) self_update ;;
  *)              display_help ;;
esac
