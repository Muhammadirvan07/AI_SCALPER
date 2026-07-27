#!/bin/zsh

set -eu

dashboard_dir="${0:A:h}"
project_dir="${dashboard_dir:h}"
venv_dir="${project_dir}/.venv-dashboard"
collector_venv_dir="${project_dir}/.venv"
frontend_dir="${project_dir}/frontend-dashboard"

if [[ ! -x "${venv_dir}/bin/uvicorn" ]]; then
  print -u2 "Environment backend belum siap: ${venv_dir}"
  print -u2 "Buat venv dan install dashboard_api/requirements.txt terlebih dahulu."
  exit 1
fi

if [[ ! -d "${frontend_dir}/node_modules" ]]; then
  print -u2 "Dependency frontend belum tersedia. Jalankan npm install."
  exit 1
fi

export AI_SCALPER_ROOT="${AI_SCALPER_ROOT:-${project_dir}}"
export AI_SCALPER_API_HOST="${AI_SCALPER_API_HOST:-127.0.0.1}"
export AI_SCALPER_API_PORT="${AI_SCALPER_API_PORT:-8000}"
export AI_SCALPER_ENABLE_MARKET_UPDATER="${AI_SCALPER_ENABLE_MARKET_UPDATER:-true}"

api_pid=""
frontend_pid=""
updater_pid=""

cleanup() {
  [[ -n "${updater_pid}" ]] && kill "${updater_pid}" 2>/dev/null || true
  [[ -n "${frontend_pid}" ]] && kill "${frontend_pid}" 2>/dev/null || true
  [[ -n "${api_pid}" ]] && kill "${api_pid}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

cd "${project_dir}"
"${venv_dir}/bin/uvicorn" dashboard_api.app.main:app \
  --host "${AI_SCALPER_API_HOST}" \
  --port "${AI_SCALPER_API_PORT}" &
api_pid=$!

if [[ "${AI_SCALPER_ENABLE_MARKET_UPDATER:l}" == "true" ]]; then
  if [[ ! -x "${collector_venv_dir}/bin/python" ]]; then
    print -u2 "Environment collector belum siap: ${collector_venv_dir}"
    print -u2 "Updater dilewati; API dan frontend tetap dijalankan."
  elif [[ ! -f "${project_dir}/market_data_updater.py" ]]; then
    print -u2 "market_data_updater.py tidak ditemukan; updater dilewati."
  else
    cd "${project_dir}"
    "${collector_venv_dir}/bin/python" "${project_dir}/market_data_updater.py" &
    updater_pid=$!
  fi
fi

cd "${frontend_dir}"
npm run dev -- --host 127.0.0.1 --port 5173 &
frontend_pid=$!

print "Dashboard API PID: ${api_pid}"
print "Frontend PID: ${frontend_pid}"
[[ -n "${updater_pid}" ]] && print "Market updater PID: ${updater_pid}"
print "Dashboard: http://localhost:5173/#overview"
print "Tekan Ctrl+C untuk menghentikan seluruh proses dashboard."

wait
