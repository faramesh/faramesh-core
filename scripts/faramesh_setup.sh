#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIZARD_SCRIPT="$CORE_DIR/scripts/faramesh_govern_wizard.sh"
SETUP_CACHE_DIR="${FARAMESH_SETUP_CACHE_DIR:-$CORE_DIR/.tmp/faramesh-setup}"
LOCAL_BUILD_BIN="$SETUP_CACHE_DIR/faramesh"

normalize_yes_no() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    y|yes|true|1)
      echo "yes"
      ;;
    n|no|false|0)
      echo "no"
      ;;
    *)
      echo ""
      ;;
  esac
}

normalize_bool_for_cobra() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    y|yes|true|1|t)
      echo "true"
      ;;
    n|no|false|0|f)
      echo "false"
      ;;
    *)
      echo "$1"
      ;;
  esac
}

has_flag_prefix() {
  local prefix="$1"
  shift || true
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$prefix" || "$arg" == "$prefix="* ]]; then
      return 0
    fi
  done
  return 1
}

binary_supports_subcommand() {
  local bin="$1"
  local required_subcommand="${2:-}"
  if [[ -z "$required_subcommand" ]]; then
    return 0
  fi
  local output
  output="$("$bin" "$required_subcommand" --help 2>&1 || true)"
  if [[ "$output" == *"unknown command"* ]]; then
    return 1
  fi
  if [[ "$output" == *"Usage:"* || "$output" == *"help for"* ]]; then
    return 0
  fi
  return 1
}

resolve_faramesh_bin() {
  local required_subcommand="${1:-}"

  if [[ -n "${FARAMESH_SETUP_BIN:-}" ]] && [[ -x "${FARAMESH_SETUP_BIN}" ]]; then
    if binary_supports_subcommand "$FARAMESH_SETUP_BIN" "$required_subcommand"; then
      echo "$FARAMESH_SETUP_BIN"
      return 0
    fi
  fi

  if [[ -x "$LOCAL_BUILD_BIN" ]] && binary_supports_subcommand "$LOCAL_BUILD_BIN" "$required_subcommand"; then
    echo "$LOCAL_BUILD_BIN"
    return 0
  fi

  local candidate=""
  if type -P faramesh >/dev/null 2>&1; then
    candidate="$(type -P faramesh)"
  elif command -v faramesh >/dev/null 2>&1; then
    candidate="$(command -v faramesh)"
  fi

  if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then
    if binary_supports_subcommand "$candidate" "$required_subcommand"; then
      echo "$candidate"
      return 0
    fi
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo "no compatible faramesh binary found and Go is unavailable to build a local copy" >&2
    echo "run: bash scripts/faramesh_setup.sh install" >&2
    exit 1
  fi

  mkdir -p "$SETUP_CACHE_DIR"
  (
    cd "$CORE_DIR"
    go build -o "$LOCAL_BUILD_BIN" ./cmd/faramesh
  )

  if ! binary_supports_subcommand "$LOCAL_BUILD_BIN" "$required_subcommand"; then
    echo "built faramesh binary does not support required subcommand: $required_subcommand" >&2
    exit 1
  fi

  echo "$LOCAL_BUILD_BIN"
}

confirm_or_exit() {
  local prompt="$1"
  local answer=""
  read -r -p "$prompt [y/N]: " answer || true
  answer="$(normalize_yes_no "${answer:-no}")"
  if [[ "$answer" != "yes" ]]; then
    echo "aborted"
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Faramesh lifecycle manager (canonical setup command).

Usage:
  bash scripts/faramesh_setup.sh [command] [args]

Commands:
  flow           One guided flow: install + optional cloud pair + discover/attach/coverage/gaps/suggest + run
  start|wizard   Start governance wizard
  status         Show wizard runtime status
  stop           Stop wizard runtime
  onboard        Run onboarding preflight with strict defaults
  offboard       Run automatic code offboarding (dry-run by default)
  uninstall      Detach Faramesh from project(s), stop runtime, remove local installs
  install        Run binary installer script
  help           Show this help

Examples:
  bash scripts/faramesh_setup.sh flow
  bash scripts/faramesh_setup.sh flow --agent-cmd "python agent.py" --cloud-pair yes
  bash scripts/faramesh_setup.sh
  bash scripts/faramesh_setup.sh start --framework langchain --agent-cmd "python app.py"
  bash scripts/faramesh_setup.sh status
  bash scripts/faramesh_setup.sh stop
  bash scripts/faramesh_setup.sh onboard --policy policies/default.fpl --credential-profile production
  bash scripts/faramesh_setup.sh offboard --path /path/to/agent --apply
  bash scripts/faramesh_setup.sh uninstall --path /path/to/agent --yes
  bash scripts/faramesh_setup.sh install --no-interactive

Recommended flow for existing agent stacks (LangChain, LangGraph, DeepAgents, MCP):
  1) one-shot:   bash scripts/faramesh_setup.sh flow
  2) detach:     bash scripts/faramesh_setup.sh offboard --path <agent-project> --apply
  3) uninstall:  bash scripts/faramesh_setup.sh uninstall --path <agent-project> --yes
EOF
}

flow_usage() {
  cat <<'EOF'
Usage:
  bash scripts/faramesh_setup.sh flow [options]

Runs one guided shell flow that can:
  1) install Faramesh,
  2) optionally pair with Faramesh Horizon cloud,
  3) run discover/attach/coverage/gaps/suggest,
  4) optionally execute your agent under governance with faramesh run.

Options:
  --project-dir <dir>     Project directory for onboarding commands (default: cwd)
  --data-dir <dir>        Data directory for attach/coverage/gaps/suggest (default: <project>/.faramesh)
  --policy-out <file>     Suggested policy output path (default: <project>/suggested-policy.yaml)
  --agent-cmd <command>   Agent command to run with faramesh run
  --cloud-pair <mode>     yes|no|auto (default: auto)
  --run-now <mode>        yes|no|auto (default: auto)
  --install <mode>        yes|no|auto (default: auto)
  --yes, -y               Non-interactive mode (accept defaults)
  -h, --help              Show this help
EOF
}

uninstall_usage() {
  cat <<'EOF'
Usage:
  bash scripts/faramesh_setup.sh uninstall [options]

Options:
  --path <dir>                Project path to detach with offboard (repeatable)
  --backup-ext <ext>          Backup extension for offboard rewrites (default: .faramesh.bak)
  --remove-generated <yes|no> Remove generated faramesh/policy files (default: yes)
  --skip-offboard             Do not run project detachment
  --yes, -y                   Skip confirmation prompt
  -h, --help                  Show this help

Examples:
  bash scripts/faramesh_setup.sh uninstall --path ./my-agent
  bash scripts/faramesh_setup.sh uninstall --path ./agent-a --path ./agent-b --yes
  bash scripts/faramesh_setup.sh uninstall --skip-offboard --yes
EOF
}

remove_binary_if_present() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    return 0
  fi
  if [[ -w "$target" || -w "$(dirname "$target")" ]]; then
    rm -f "$target"
    echo "removed binary: $target"
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo rm -f "$target"
    echo "removed binary (sudo): $target"
    return 0
  fi
  echo "could not remove binary (permission denied): $target" >&2
  return 1
}

run_onboard() {
  local bin
  bin="$(resolve_faramesh_bin onboard)"

  local strict_default
  strict_default="$(normalize_bool_for_cobra "${FARAMESH_ONBOARD_STRICT:-true}")"
  local policy_default="${FARAMESH_POLICY_PATH:-}"
  local -a args
  args=("$@")

  local i=0
  for ((i = 0; i < ${#args[@]}; i++)); do
    if [[ "${args[$i]}" == --strict=* ]]; then
      args[$i]="--strict=$(normalize_bool_for_cobra "${args[$i]#--strict=}")"
    elif [[ "${args[$i]}" == "--strict" ]] && (( i + 1 < ${#args[@]} )); then
      args[$((i + 1))]="$(normalize_bool_for_cobra "${args[$((i + 1))]}")"
    fi
  done

  if ! has_flag_prefix "--strict" "${args[@]}"; then
    args=(--strict="$strict_default" "${args[@]}")
  fi
  if [[ -n "$policy_default" ]] && ! has_flag_prefix "--policy" "${args[@]}"; then
    args=(--policy "$policy_default" "${args[@]}")
  fi

  exec "$bin" onboard "${args[@]}"
}

run_offboard() {
  local bin
  bin="$(resolve_faramesh_bin offboard)"
  exec "$bin" offboard "$@"
}

run_flow() {
  local assume_yes=0
  local project_dir="$PWD"
  local data_dir=""
  local policy_out=""
  local agent_cmd=""
  local cloud_pair_mode="auto"
  local run_now_mode="auto"
  local install_mode="auto"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project-dir)
        project_dir="${2:-}"
        shift
        ;;
      --data-dir)
        data_dir="${2:-}"
        shift
        ;;
      --policy-out)
        policy_out="${2:-}"
        shift
        ;;
      --agent-cmd)
        agent_cmd="${2:-}"
        shift
        ;;
      --cloud-pair)
        cloud_pair_mode="${2:-}"
        shift
        ;;
      --run-now)
        run_now_mode="${2:-}"
        shift
        ;;
      --install)
        install_mode="${2:-}"
        shift
        ;;
      --yes|-y)
        assume_yes=1
        ;;
      -h|--help)
        flow_usage
        exit 0
        ;;
      *)
        echo "unknown flow option: $1" >&2
        flow_usage
        exit 1
        ;;
    esac
    shift
  done

  if [[ ! -d "$project_dir" ]]; then
    echo "project directory not found: $project_dir" >&2
    exit 1
  fi

  if [[ -z "$data_dir" ]]; then
    data_dir="$project_dir/.faramesh"
  fi
  mkdir -p "$data_dir"

  if [[ -z "$policy_out" ]]; then
    policy_out="$project_dir/suggested-policy.yaml"
  fi

  cloud_pair_mode="$(normalize_yes_no "$cloud_pair_mode")"
  if [[ -z "$cloud_pair_mode" ]]; then
    cloud_pair_mode="auto"
  fi

  run_now_mode="$(normalize_yes_no "$run_now_mode")"
  if [[ -z "$run_now_mode" ]]; then
    run_now_mode="auto"
  fi

  install_mode="$(normalize_yes_no "$install_mode")"
  if [[ -z "$install_mode" ]]; then
    install_mode="auto"
  fi

  local do_install="no"
  if [[ "$install_mode" == "yes" ]]; then
    do_install="yes"
  elif [[ "$install_mode" == "auto" ]]; then
    if ! command -v faramesh >/dev/null 2>&1; then
      do_install="yes"
    fi
  fi

  if [[ "$do_install" == "yes" ]]; then
    echo "[flow] installing faramesh via install.sh"
    if [[ "$assume_yes" -eq 1 ]]; then
      bash "$CORE_DIR/install.sh" --no-interactive
    else
      bash "$CORE_DIR/install.sh"
    fi
  fi

  local bin
  bin="$(resolve_faramesh_bin discover)"

  local do_cloud_pair="no"
  if [[ "$cloud_pair_mode" == "yes" ]]; then
    do_cloud_pair="yes"
  elif [[ "$cloud_pair_mode" == "auto" && "$assume_yes" -eq 0 ]]; then
    local ans=""
    read -r -p "pair with Faramesh Horizon cloud now? [y/N]: " ans || true
    ans="$(normalize_yes_no "${ans:-no}")"
    if [[ "$ans" == "yes" ]]; then
      do_cloud_pair="yes"
    fi
  fi

  if [[ "$do_cloud_pair" == "yes" ]]; then
    echo "[flow] running cloud auth login"
    "$bin" auth login || echo "cloud login returned non-zero; continuing local flow"
  fi

  echo "[flow] discover"
  (cd "$project_dir" && "$bin" discover)

  echo "[flow] attach"
  (cd "$project_dir" && "$bin" attach --interactive=false --data-dir "$data_dir")

  echo "[flow] coverage"
  (cd "$project_dir" && "$bin" coverage --data-dir "$data_dir")

  echo "[flow] suggest"
  (cd "$project_dir" && "$bin" suggest --data-dir "$data_dir" --out "$policy_out")

  echo "[flow] gaps"
  (cd "$project_dir" && "$bin" gaps --data-dir "$data_dir" --policy "$policy_out")

  local do_run_now="no"
  if [[ "$run_now_mode" == "yes" ]]; then
    do_run_now="yes"
  elif [[ "$run_now_mode" == "auto" && "$assume_yes" -eq 0 ]]; then
    local run_ans=""
    read -r -p "run your agent under governance now? [Y/n]: " run_ans || true
    run_ans="$(normalize_yes_no "${run_ans:-yes}")"
    if [[ "$run_ans" != "no" ]]; then
      do_run_now="yes"
    fi
  fi

  if [[ "$do_run_now" == "yes" ]]; then
    if [[ -z "$agent_cmd" && "$assume_yes" -eq 0 ]]; then
      read -r -p "agent command (example: python agent.py): " agent_cmd || true
    fi

    if [[ -n "$agent_cmd" ]]; then
      echo "[flow] run (policy=$policy_out): $agent_cmd"
      (cd "$project_dir" && "$bin" run --policy "$policy_out" -- bash -lc "$agent_cmd")
      return 0
    fi
  fi

  cat <<EOF

[flow] setup complete.

Suggested policy:
  $policy_out

Next commands:
  cd "$project_dir"
  faramesh run --policy "$policy_out" -- <your-agent-command>
  faramesh pack search
  faramesh pack install <pack-ref> --mode shadow
  faramesh pack enforce <pack-ref>
EOF
}

run_uninstall() {
  local assume_yes=0
  local skip_offboard="no"
  local remove_generated="yes"
  local backup_ext=".faramesh.bak"
  local -a project_paths=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        project_paths+=("${2:-}")
        shift
        ;;
      --backup-ext)
        backup_ext="${2:-}"
        shift
        ;;
      --remove-generated)
        remove_generated="${2:-}"
        shift
        ;;
      --skip-offboard)
        skip_offboard="yes"
        ;;
      --yes|-y)
        assume_yes=1
        ;;
      -h|--help)
        uninstall_usage
        exit 0
        ;;
      *)
        echo "unknown uninstall option: $1" >&2
        uninstall_usage
        exit 1
        ;;
    esac
    shift
  done

  remove_generated="$(normalize_yes_no "$remove_generated")"
  if [[ -z "$remove_generated" ]]; then
    echo "invalid --remove-generated value (expected yes|no)" >&2
    exit 1
  fi

  if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -eq 0 ]]; then
    echo "no --path supplied; project code detach will be skipped"
  fi

  if [[ "$assume_yes" -eq 0 ]]; then
    echo "this will:"
    echo "  1) stop wizard-managed Faramesh runtime"
    if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -gt 0 ]]; then
      echo "  2) apply offboard rewrites for provided project path(s)"
    fi
    echo "  3) remove setup-local runtime state"
    echo "  4) remove common local faramesh binaries when present"
    confirm_or_exit "continue uninstall"
  fi

  if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -gt 0 ]]; then
    local bin
    bin="$(resolve_faramesh_bin offboard)"
    local path
    for path in "${project_paths[@]}"; do
      if [[ -z "$path" ]]; then
        continue
      fi
      local -a offboard_cmd
      offboard_cmd=(offboard --path "$path" --apply --backup-ext "$backup_ext")
      if [[ "$remove_generated" == "yes" ]]; then
        offboard_cmd+=(--remove-generated)
      fi
      "$bin" "${offboard_cmd[@]}"
    done
  fi

  bash "$WIZARD_SCRIPT" stop >/dev/null 2>&1 || true

  rm -rf "${FARAMESH_WIZARD_DIR:-$CORE_DIR/.tmp/faramesh-wizard}"
  rm -f "$LOCAL_BUILD_BIN"

  remove_binary_if_present "/usr/local/bin/faramesh" || true
  remove_binary_if_present "$HOME/.local/bin/faramesh" || true

  local detected_bin=""
  if type -P faramesh >/dev/null 2>&1; then
    detected_bin="$(type -P faramesh)"
  elif command -v faramesh >/dev/null 2>&1; then
    detected_bin="$(command -v faramesh)"
  fi

  if [[ -n "$detected_bin" ]] && [[ -x "$detected_bin" ]]; then
    case "$detected_bin" in
      /opt/homebrew/*|/usr/local/Cellar/*)
        echo "homebrew-managed faramesh detected at $detected_bin"
        echo "run: brew uninstall faramesh/tap/faramesh"
        ;;
      *)
        if [[ "$detected_bin" != "/usr/local/bin/faramesh" && "$detected_bin" != "$HOME/.local/bin/faramesh" ]]; then
          echo "additional faramesh binary still on PATH: $detected_bin"
          echo "remove it manually if you want full uninstall"
        fi
        ;;
    esac
  fi

  echo "uninstall flow complete"
}

if [[ $# -eq 0 ]]; then
  run_flow
  exit 0
fi

case "$1" in
  flow)
    shift
    run_flow "$@"
    ;;
  start|wizard)
    shift
    exec bash "$WIZARD_SCRIPT" "$@"
    ;;
  status|stop)
    cmd="$1"
    shift
    exec bash "$WIZARD_SCRIPT" "$cmd" "$@"
    ;;
  onboard)
    shift
    run_onboard "$@"
    ;;
  offboard|detach)
    shift
    run_offboard "$@"
    ;;
  uninstall)
    shift
    run_uninstall "$@"
    ;;
  install)
    shift
    exec bash "$CORE_DIR/install.sh" "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  --*)
    exec bash "$WIZARD_SCRIPT" "$@"
    ;;
  *)
    echo "unknown command: $1" >&2
    usage
    exit 1
    ;;
esac