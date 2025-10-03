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
# Works on most Linux distros.
#

set -euo pipefail
IFS=$'\n\t'

BUGBAY_NAME="BugBay"
BUGBAY_BRAND="Hidden Investigations"
BUGBAY_BRAND_URL="HiddenInvestigations.net"

# Expected repo: https://github.com/Hidden-Investigations/bugbay
BUGBAY_UPDATE_URL="https://raw.githubusercontent.com/Hidden-Investigations/bugbay/main/bugbay.sh"

ETC_HOSTS=/etc/hosts

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

What is BugBay?  A quick CLI to spin up vulnerable web apps with Docker and /etc/hosts aliases.
EOF
}

############################################
# Utils / env checks
############################################
_die() { echo "ERROR: $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_cmd() { have_cmd "$1" || _die "'$1' not found. Please install it."; }
ensure_docker_cli() { ensure_cmd docker; }

# Prefer systemd if present
if have_cmd systemctl; then
  docker_status() { systemctl is-active docker >/dev/null 2>&1; }
  docker_start()  { sudo systemctl start docker; }
else
  docker_status() { sudo service docker status 2>/dev/null | grep -q "active (running)"; }
  docker_start()  { sudo service docker start; }
fi

ensure_docker_running() {
  ensure_docker_cli
  if ! docker_status; then
    echo "Docker is not running."
    printf "Start Docker now (y/n)? "
    read -r answer || true
    if printf '%s' "$answer" | grep -iq "^y"; then docker_start; else _die "Docker must be running for this command."; fi
  fi
}

# Compose wrapper (supports both Docker Compose v2 and legacy docker-compose)
dc() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@" || sudo docker compose "$@"
  elif have_cmd docker-compose; then
    docker-compose "$@" || sudo docker-compose "$@"
  else
    _die "docker compose not found (need Docker Compose v2 or 'docker-compose')."
  fi
}

check_listen() {
  # Return 0 if something is listening on ip:port OR 0.0.0.0:port / [::]:port
  local ip="$1" port="$2"
  if have_cmd ss; then
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "^($ip|0\.0\.0\.0|\[::\]):$port$"
  elif have_cmd netstat; then
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "^($ip|0\.0\.0\.0|\[::\]):$port$"
  else
    return 1
  fi
}

############################################
# Help (full)
############################################
display_help() {
ascii_logo
cat <<EOF

$(bold "$BUGBAY_NAME – Local Pentest Lab Manager (Docker + hosts aliases)")
Brand: $BUGBAY_BRAND

Usage:
  $(bold "bugbay.sh {list|status|info|start|startpublic|stop|pull|logs|shell|rm|self-update} [lab] [args...]")

Common:
  $(bold "list")                  Show a table of labs (image/ports/type/notes)
  $(bold "info <lab>")            Show detailed info (image, URLs, creds, notes)
  $(bold "status [all]")          Show running labs (or all with 'all')
  $(bold "start <lab>")           Launch a lab on loopback + hosts alias
  $(bold "stop <lab>")            Stop a lab and clean hosts

Power:
  $(bold "startpublic <lab> [ip] [port]")  Expose a lab on your LAN  $(c 3 "WARNING")
  $(bold "pull <lab|all>")                 Pull latest images
  $(bold "logs <lab>")                     Tail container logs
  $(bold "shell <lab>")                    Open a shell in a running container
  $(bold "rm <lab>")                       Stop & remove containers; clean hosts
  $(bold "self-update")                    Update script from fixed GitHub URL

Examples:
  ./bugbay.sh list
  ./bugbay.sh info dvwa
  ./bugbay.sh start dvwa
  ./bugbay.sh startpublic dvwa 192.168.0.42 8080
  ./bugbay.sh logs juiceshop
  ./bugbay.sh pull all
  ./bugbay.sh shell bwapp

EOF
  exit 1
}

############################################
# /etc/hosts helpers (safe: mktemp + flock with fallback)
############################################
_has_flock() { have_cmd flock; }

removehost() {
  local host="${1:?hostname required}"
  if grep -qw "$host" "$ETC_HOSTS"; then
    echo "Removing $host from $ETC_HOSTS"
    local tmp; tmp="$(mktemp)"
    if _has_flock; then
      sudo sh -c "
        umask 022
        flock -x 9
        awk -v h='$host' '{
          keep=1
          for (i=2;i<=NF;i++) if (\$i==h) { keep=0; break }
          if (keep) print \$0
        }' '$ETC_HOSTS' > '$tmp' &&
        mv '$tmp' '$ETC_HOSTS'
      " 9> /tmp/.bugbay_hosts.lock
    else
      sudo sh -c "
        umask 022
        awk -v h='$host' '{
          keep=1
          for (i=2;i<=NF;i++) if (\$i==h) { keep=0; break }
          if (keep) print \$0
        }' '$ETC_HOSTS' > '$tmp' &&
        mv '$tmp' '$ETC_HOSTS'
      "
    fi
  fi
}

addhost() { # addhost "127.5.0.1" "bwapp"
  local ip="${1:?ip required}" host="${2:?host required}"
  if grep -qw "$host" "$ETC_HOSTS"; then
    echo "$host already exists in $ETC_HOSTS"; return 0
  fi
  local tmp; tmp="$(mktemp)"
  if _has_flock; then
    sudo sh -c "
      umask 022
      flock -x 9
      cat '$ETC_HOSTS' > '$tmp'
      printf '%s\t%s\n' '$ip' '$host' >> '$tmp'
      mv '$tmp' '$ETC_HOSTS'
    " 9> /tmp/.bugbay_hosts.lock
  else
    sudo sh -c "
      umask 022
      cat '$ETC_HOSTS' > '$tmp'
      printf '%s\t%s\n' '$ip' '$host' >> '$tmp'
      mv '$tmp' '$ETC_HOSTS'
    "
  fi
  grep -qw "$host" "$ETC_HOSTS" || _die "Failed to add $host"
}

############################################
# Registry (single source of truth)
# Fields: key|Name|Type|Image|DefaultPorts|LoopbackIP|URLHint|ShortNote|Creds
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
securityshepherd|Security Shepherd|single|ismisepaul/securityshepherd|80|127.11.0.1|http://securityshepherd|OWASP training app|
vulnerablewordpress|Vuln WordPress|single|eystsen/vulnerablewordpress|80 (+3306 loopback)|127.12.0.1|http://vulnerablewordpress|WP+MySQL demo|
securityninjas|Security Ninjas|single|opendns/security-ninjas|80|127.13.0.1|http://securityninjas|OpenDNS training app|
altoro|Altoro Mutual|single|eystsen/altoro|8080|127.14.0.1|http://altoro|Bank demo|jsmith/demo1234; admin/admin
graphql|Vulnerable GraphQL API|single|carvesystems/vulnerable-graphql-api|3000|127.15.0.1|http://graphql|GraphQL vulns|
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
crapi|OWASP crAPI|compose|owasp/crapi (compose)|8888 (+8025)|N/A|http://localhost:8888|Compose multi-service API lab|
vulhub|Vulhub|compose|various (compose)|varies|N/A|https://github.com/vulhub/vulhub|CVE labs via compose|
DB
}

############################################
# Info / List / Status (built from registry)
############################################
print_info() {
  local key="${1:?info needs <lab>}"
  local line
  line="$(lab_db | awk -F'|' -v k="$key" '$1==k{print $0}')"
  [ -z "$line" ] && _die "Unknown lab: $key"
  IFS='|' read -r _key name type image ports ip url note creds <<<"$line"
  ascii_logo
  echo
  echo "$(bold "$name")"
  printf "%-12s %s\n" "Key:" "$key"
  printf "%-12s %s\n" "Type:" "$type"
  printf "%-12s %s\n" "Image:" "$image"
  printf "%-12s %s\n" "Default:" "$ports"
  printf "%-12s %s\n" "Loopback:" "${ip}"
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
  ascii_logo
  echo
  echo "$(bold "Available labs") — $(dim "use: ./bugbay.sh info <lab>")"
  printf "%-20s  %-6s  %-30s  %-18s  %s\n" "$(bold 'NAME')" "$(bold 'TYPE')" "$(bold 'IMAGE')" "$(bold 'DEFAULT PORTS')" "$(bold 'NOTES')"
  printf "%-20s  %-6s  %-30s  %-18s  %s\n" "--------------------" "------" "------------------------------" "------------------" "-------------------------------"
  lab_db | while IFS='|' read -r key name type image ports ip url note creds; do
    printf "%-20s  %-6s  %-30s  %-18s  %s\n" "$key" "$type" "$image" "$ports" "$note"
  done
  echo
  echo "Example:  $(bold "./bugbay.sh info dvwa")"
}

project_status() {
  ensure_docker_running
  local show_all="${1:-running}"
  printf "%-28s  %-7s  %s\n" "$(bold 'Application')" "$(bold 'State')" "$(bold 'Info')"
  printf "%-28s  %-7s  %s\n" "----------------------------" "-------" "-----------------------------"
  local total=0 running=0 public=0
  lab_db | while IFS='|' read -r key name type image ports ip url note creds; do
    [ "$type" = "compose" ] && continue
    total=$((total+1))
    local cid_local cid_pub
    cid_local="$(sudo docker ps -q -f "name=^/${key}$" 2>/dev/null || true)"
    cid_pub="$(sudo docker ps -q -f "name=^/${key}public$" 2>/dev/null || true)"
    if [ -n "$cid_local" ] || [ -n "$cid_pub" ] || [ "$show_all" = "all" ]; then
      if [ -n "$cid_local" ]; then
        printf "%-28s  %s  %s\n" "$name" "$(c 2 'RUNNING')" "$(dim "${url:-}")"
        running=$((running+1))
      fi
      if [ -n "$cid_pub" ]; then
        printf "%-28s  %s\n" "$name" "$(c 1 'PUBLIC')"
        public=$((public+1))
      fi
      if [ -z "$cid_local" ] && [ -z "$cid_pub" ] && [ "$show_all" = "all" ]; then
        printf "%-28s  %s\n" "$name" "$(dim 'stopped')"
      fi
    fi
  done
  echo
  printf "%s %s, %s %s, %s %s\n" \
    "$(bold 'Apps:')" "$total" \
    "$(bold 'Running(local):')" "$running" \
    "$(bold 'Running(public):')" "$public"
  echo "$(dim "Compose labs: crAPI, Vulhub (use docker compose)")"
}

############################################
# Docker helpers (single-container labs)
############################################
project_start() {
  ensure_docker_running
  local fullname="$1" projectname="$2" dockername="$3" ip="$4" port="$5"
  local port2="${6-}" extra="${7-}"
  echo "Starting $fullname"
  addhost "$ip" "$projectname"
  local existing
  existing="$(sudo docker ps -aq -f "name=^/${projectname}$")"
  if [ -n "$existing" ]; then
    echo "docker start $projectname"
    sudo docker start "$projectname" >/dev/null
  else
    if [ -n "$port2" ]; then
      echo "docker run --name $projectname -d -p $ip:80:$port -p $ip:$port2:$port2 $extra $dockername"
      # shellcheck disable=SC2086
      sudo docker run --name "$projectname" -d -p "$ip:80:$port" -p "$ip:$port2:$port2" $extra "$dockername" >/dev/null
    else
      echo "docker run --name $projectname -d -p $ip:80:$port $extra $dockername"
      # shellcheck disable=SC2086
      sudo docker run --name "$projectname" -d -p "$ip:80:$port" $extra "$dockername" >/dev/null
    fi
  fi
  echo "$(c 2 "DONE")  http://$projectname   or   http://$ip"
}

project_startpublic() {
  ensure_docker_running
  local fullname="$1" projectname="${2}public" dockername="$3" internalport="$4" publicip="$5" port="$6" extra="${7-}"
  echo "Starting $fullname (public)"
  local existing
  existing="$(sudo docker ps -aq -f "name=^/${projectname}$")"
  if [ -n "$existing" ]; then
    echo "docker start $projectname"
    sudo docker start "$projectname" >/dev/null
  else
    echo "docker run --name $projectname -d -p $publicip:$port:$internalport $extra $dockername"
    # shellcheck disable=SC2086
    sudo docker run --name "$projectname" -d -p "$publicip:$port:$internalport" $extra "$dockername" >/dev/null
  fi
  if [ "$port" -eq 80 ]; then echo "$(c 1 "PUBLIC")  http://$publicip"; else echo "$(c 1 "PUBLIC")  http://$publicip:$port"; fi
}

project_stop() {
  ensure_docker_running
  local fullname="$1" projectname="$2"
  local cid
  cid="$(sudo docker ps -q -f "name=^/${projectname}$")"
  if [ -n "$cid" ]; then
    echo "Stopping $fullname"; sudo docker stop "$projectname" >/dev/null; removehost "$projectname"
  fi
  local public="${projectname}public"
  cid="$(sudo docker ps -q -f "name=^/${public}$")"
  [ -n "$cid" ] && { echo "Stopping $fullname (public)"; sudo docker stop "$public" >/dev/null; }
}

project_rm() {
  ensure_docker_running
  local fullname="$1" projectname="$2"
  project_stop "$fullname" "$projectname"
  [ -n "$(sudo docker ps -a -q -f "name=^/${projectname}$")" ] && sudo docker rm "$projectname" >/dev/null || true
  [ -n "$(sudo docker ps -a -q -f "name=^/${projectname}public$")" ] && sudo docker rm "${projectname}public" >/dev/null || true
  removehost "$projectname" || true
}

############################################
# Compose helpers (crAPI, Vulhub)
############################################
compose_start() {
  ensure_docker_running
  ensure_cmd git
  local name="$1" git_url="$2" compose_dir="$3" hint="$4"
  echo "Starting $name via docker compose..."
  mkdir -p "$HOME/.bugbay"
  if [ ! -d "$HOME/.bugbay/$name" ]; then
    git clone "$git_url" "$HOME/.bugbay/$name"
  else
    ( cd "$HOME/.bugbay/$name" && git pull --ff-only >/dev/null )
  fi
  ( cd "$HOME/.bugbay/$name/$compose_dir" && dc pull && dc up -d )
  echo "$name started. Try: $hint"
}

compose_stop() {
  ensure_docker_running
  local name="$1" compose_dir="$2"
  if [ -d "$HOME/.bugbay/$name/$compose_dir" ]; then
    ( cd "$HOME/.bugbay/$name/$compose_dir" && dc down )
  else
    echo "Compose dir for $name not found."
  fi
}

compose_info() { echo "$1 uses multiple compose labs. Browse: $2"; }

############################################
# Extra: pull/logs/shell/rm/self-update
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
      pierrickv/hackazon ismisepaul/securityshepherd
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
      securityshepherd) pull_image "ismisepaul/securityshepherd" ;;
      crapi|vulhub) echo "Use compose directories to pull these." ;;
      *) _die "Unknown lab: $target" ;;
    esac
  fi
}

logs_dispatch() {
  ensure_docker_running
  local app="${1-}"; [ -z "$app" ] && _die "logs needs <lab>"
  local name="$app"
  if [ -z "$(sudo docker ps -a -q -f "name=^/${name}$")" ]; then
    if [ -n "$(sudo docker ps -a -q -f "name=^/${name}public$")" ]; then name="${name}public"; else _die "No container found: $app"; fi
  fi
  sudo docker logs -f "$name"
}

shell_dispatch() {
  ensure_docker_running
  local app="${1-}"; [ -z "$app" ] && _die "shell needs <lab>"
  local name="$app"
  if [ -z "$(sudo docker ps -q -f "name=^/${name}$")" ]; then
    if [ -n "$(sudo docker ps -q -f "name=^/${name}public$")" ]; then name="${name}public"; else _die "Container not running: $app"; fi
  fi
  if sudo docker exec "$name" bash -lc 'true' 2>/dev/null; then sudo docker exec -it "$name" bash; else sudo docker exec -it "$name" sh; fi
}

rm_dispatch() {
  ensure_docker_running
  local app="${1-}"; [ -z "$app" ] && _die "rm needs <lab>"
  case "$app" in
    crapi|vulhub) echo "Use compose down for $app."; ;;
    *) project_rm "$app" "$app" ;;
  esac
}

self_update() {
  ensure_cmd curl
  echo "Downloading: $BUGBAY_UPDATE_URL"
  local tmp
  tmp="$(mktemp)"
  if curl -fsSL "$BUGBAY_UPDATE_URL" -o "$tmp"; then
    chmod +x "$tmp"
    cp "$0" "${0}.bak.$(date +%s)"
    mv "$tmp" "$0"
    echo "Updated. Backup saved as ${0}.bak.<timestamp>"
  else
    rm -f "$tmp" || true
    _die "Download failed."
  fi
}

############################################
# Dispatch (single + compose)
############################################
project_start_dispatch() {
  case "$1" in
    bwapp) project_start "bWAPP" "bwapp" "raesene/bwapp" "127.5.0.1" "80";;
    webgoat7) project_start "WebGoat 7.1" "webgoat7" "webgoat/webgoat-7.1" "127.6.0.1" "8080";;
    webgoat8) project_start "WebGoat 8.0" "webgoat8" "webgoat/webgoat-8.0" "127.7.0.1" "8080";;
    webgoat81) project_start "WebGoat 8.1" "webgoat81" "webgoat/goatandwolf" "127.17.0.1" "8080";;
    dvwa) project_start "DVWA" "dvwa" "vulnerables/web-dvwa" "127.8.0.1" "80";;
    mutillidae) project_start "Mutillidae II" "mutillidae" "citizenstig/nowasp" "127.9.0.1" "80";;
    juiceshop) project_start "OWASP Juice Shop" "juiceshop" "bkimminich/juice-shop" "127.10.0.1" "3000";;
    securityshepherd) project_start "Security Shepherd" "securityshepherd" "ismisepaul/securityshepherd" "127.11.0.1" "80";;
    vulnerablewordpress) project_start "Vuln WordPress" "vulnerablewordpress" "eystsen/vulnerablewordpress" "127.12.0.1" "80" "3306";;
    securityninjas) project_start "OpenDNS Security Ninjas" "securityninjas" "opendns/security-ninjas" "127.13.0.1" "80";;
    altoro) project_start "Altoro Mutual" "altoro" "eystsen/altoro" "127.14.0.1" "8080";;
    graphql) project_start "Vulnerable GraphQL API" "graphql" "carvesystems/vulnerable-graphql-api" "127.15.0.1" "3000";;
    railsgoat) project_start "RailsGoat" "railsgoat" "owasp/railsgoat" "127.18.0.1" "3000";;
    dvna) project_start "DVNA" "dvna" "appsecco/dvna" "127.19.0.1" "9090";;
    nodegoat) project_start "NodeGoat (image)" "nodegoat" "vulnerables/web-owasp-nodegoat" "127.20.0.1" "4000";;
    brokencrystals) project_start "BrokenCrystals" "brokencrystals" "neuralegion/brokencrystals" "127.21.0.1" "3000";;
    vulnerableapp) project_start "OWASP VulnerableApp" "vulnerableapp" "sasanlabs/owasp-vulnerableapp" "127.22.0.1" "9090";;
    dvga) project_start "DVGA (GraphQL)" "dvga" "dolevf/dvga" "127.23.0.1" "5013";;
    xvwa) project_start "XVWA" "xvwa" "tuxotron/xvwa" "127.24.0.1" "80";;
    dvws) project_start "DVWS" "dvws" "tssoffsec/dvws" "127.25.0.1" "65412";;
    vampi) project_start "VAmPI" "vampi" "erev0s/vampi" "127.26.0.1" "5000" "" "-e vulnerable=1";;
    bodgeit) project_start "BodgeIt Store" "bodgeit" "psiinon/bodgeit" "127.27.0.1" "8080";;
    wrongsecrets) project_start "OWASP WrongSecrets" "wrongsecrets" "jeroenwillemsen/wrongsecrets" "127.28.0.1" "8080";;
    hackazon) project_start "Hackazon" "hackazon" "pierrickv/hackazon" "127.29.0.1" "80";;
    crapi) compose_start "crAPI" "https://github.com/OWASP/crAPI" "deploy/docker" "http://localhost:8888";;
    vulhub) compose_info "vulhub" "https://github.com/vulhub/vulhub";;
    *) _die "Unknown lab: $1";;
  esac
}

project_startpublic_dispatch() {
  local publicip="$2" port="$3"
  case "$1" in
    bwapp) project_startpublic "bWAPP" "bwapp" "raesene/bwapp" "80" "$publicip" "$port" ;;
    webgoat7) project_startpublic "WebGoat 7.1" "webgoat7" "webgoat/webgoat-7.1" "8080" "$publicip" "$port" ;;
    webgoat8) project_startpublic "WebGoat 8.0" "webgoat8" "webgoat/webgoat-8.0" "8080" "$publicip" "$port" ;;
    webgoat81) project_startpublic "WebGoat 8.1" "webgoat81" "webgoat/goatandwolf" "8080" "$publicip" "$port" ;;
    dvwa) project_startpublic "DVWA" "dvwa" "vulnerables/web-dvwa" "80" "$publicip" "$port" ;;
    mutillidae) project_startpublic "Mutillidae II" "mutillidae" "citizenstig/nowasp" "80" "$publicip" "$port" ;;
    juiceshop) project_startpublic "OWASP Juice Shop" "juiceshop" "bkimminich/juice-shop" "3000" "$publicip" "$port" ;;
    securityshepherd) project_startpublic "Security Shepherd" "securityshepherd" "ismisepaul/securityshepherd" "80" "$publicip" "$port" ;;
    vulnerablewordpress) project_startpublic "Vuln WordPress" "vulnerablewordpress" "eystsen/vulnerablewordpress" "80" "$publicip" "$port" ;;
    securityninjas) project_startpublic "Security Ninjas" "securityninjas" "opendns/security-ninjas" "80" "$publicip" "$port" ;;
    altoro) project_startpublic "Altoro Mutual" "altoro" "eystsen/altoro" "8080" "$publicip" "$port" ;;
    graphql) project_startpublic "Vulnerable GraphQL" "graphql" "carvesystems/vulnerable-graphql-api" "3000" "$publicip" "$port" ;;
    railsgoat) project_startpublic "RailsGoat" "railsgoat" "owasp/railsgoat" "3000" "$publicip" "$port" ;;
    dvna) project_startpublic "DVNA" "dvna" "appsecco/dvna" "9090" "$publicip" "$port" ;;
    nodegoat) project_startpublic "NodeGoat" "nodegoat" "vulnerables/web-owasp-nodegoat" "4000" "$publicip" "$port" ;;
    brokencrystals) project_startpublic "BrokenCrystals" "brokencrystals" "neuralegion/brokencrystals" "3000" "$publicip" "$port" ;;
    vulnerableapp) project_startpublic "OWASP VulnerableApp" "vulnerableapp" "sasanlabs/owasp-vulnerableapp" "9090" "$publicip" "$port" ;;
    dvga) project_startpublic "DVGA (GraphQL)" "dvga" "dolevf/dvga" "5013" "$publicip" "$port" ;;
    xvwa) project_startpublic "XVWA" "xvwa" "tuxotron/xvwa" "80" "$publicip" "$port" ;;
    dvws) project_startpublic "DVWS" "dvws" "tssoffsec/dvws" "65412" "$publicip" "$port" ;;
    vampi) project_startpublic "VAmPI" "vampi" "erev0s/vampi" "5000" "$publicip" "$port" "-e vulnerable=1" ;;
    bodgeit) project_startpublic "BodgeIt" "bodgeit" "psiinon/bodgeit" "8080" "$publicip" "$port" ;;
    wrongsecrets) project_startpublic "WrongSecrets" "wrongsecrets" "jeroenwillemsen/wrongsecrets" "8080" "$publicip" "$port" ;;
    hackazon) project_startpublic "Hackazon" "hackazon" "pierrickv/hackazon" "80" "$publicip" "$port" ;;
    crapi|vulhub) echo "Public mode not supported for compose labs ($1) – adjust compose."; ;;
    *) _die "Unknown lab: $1" ;;
  esac
}

project_stop_dispatch() {
  case "$1" in
    bwapp|webgoat7|webgoat8|webgoat81|dvwa|mutillidae|juiceshop|securityshepherd|vulnerablewordpress|securityninjas|altoro|graphql|railsgoat|dvna|nodegoat|brokencrystals|vulnerableapp|dvga|xvwa|dvws|vampi|bodgeit|wrongsecrets|hackazon)
      project_stop "$1" "$1" ;;
    crapi) compose_stop "crapi" "deploy/docker" ;;
    vulhub) echo "Vulhub: run docker compose down in the chosen lab dir." ;;
    *) _die "Unknown lab: $1" ;;
  esac
}

############################################
# Quick Start (no args) — no sudo prompt
############################################
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
# Main
############################################
case "${1-}" in
  help|-h|--help) display_help ;;
  start)
    [ -z "${2-}" ] && { echo "usage: $0 start <lab>"; exit 1; }
    project_start_dispatch "$2"
  ;;
  startpublic)
    [ -z "${2-}" ] && { echo "usage: $0 startpublic <lab> [ip] [port]"; exit 1; }
    port="${4-80}"
    if [ -n "${3-}" ]; then publicip="$3"; else publicip=$(hostname -I | awk '{print $1}'); fi
    if check_listen "$publicip" "$port"; then _die "$publicip already listening on $port"; fi
    project_startpublic_dispatch "$2" "$publicip" "$port"
    echo "$(c 3 "WARNING") expose only in trusted labs."
  ;;
  stop)
    [ -z "${2-}" ] && { echo "usage: $0 stop <lab>"; exit 1; }
    project_stop_dispatch "$2"
  ;;
  rm)           rm_dispatch "${2-}" ;;
  logs)         logs_dispatch "${2-}" ;;
  shell)        shell_dispatch "${2-}" ;;
  pull)         pull_dispatch "${2-}" ;;
  status)       if [ "${2-}" = "all" ]; then project_status "all"; else project_status "running"; fi ;;
  list)         list ;;
  info)         [ -z "${2-}" ] && { echo "usage: $0 info <lab>"; exit 1; }; print_info "$2" ;;
  self-update|selfupdate) self_update ;;
  "")           quick_start ;;
  *)            display_help ;;
esac
