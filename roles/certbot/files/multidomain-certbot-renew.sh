#!/usr/bin/env bash

set -e

. /etc/certbot/renew.rc

TEMP_DIRECTORY=$(mktemp --directory)

trap_with_arg() {
  func="$1" ; shift
  for sig
  do
    trap "$func $sig" "$sig"
  done
}

func_trap() {
  echo "Trapped: $1"
  exit_hook
}

exit_hook() {
  # clean up
  rm -rf "${TEMP_DIRECTORY}" 2> /dev/null
  rm -vf "${CERTBOT_ACME_DIR}/.well-known/acme-challenge/*"
}
trap_with_arg func_trap INT TERM QUIT EXIT

# trap exit_hook INT TERM QUIT EXIT

current_certificates() {
  echo "current certificates"
  certbot certificates
}

define_cert_file() {

  local domain="${1}"

  echo "${CERTBOT_CONF_DIR}/live/${domain}/fullchain.pem"
}

define_certbot_opts() {
  local domain="${1}"
  local expand="${2:-}"
  local CERTBOT_CERT_FILE=$(define_cert_file ${domain})

  echo "${expand} --webroot \
  --webroot-path ${CERTBOT_ACME_DIR} \
  --rsa-key-size ${CERTBOT_RSA_KEY_SIZE} \
  --cert-path /etc/letsencrypt/live/${domain} \
  --agree-tos \
  --email ${CERTBOT_EMAIL} \
  -n"
}

letsencrypt_certificates() {

  local domain="${1}"
  local CERTBOT_CERT_FILE=$(define_cert_file ${domain})

  if [ -f ${CERTBOT_CERT_FILE} ]
  then
    # Let's check, if multiple CN are used
    ca_domains=$(openssl x509 \
      -in ${CERTBOT_CERT_FILE} \
      -text \
      -noout | \
        grep 'DNS:' | \
        sed -r -e 's/^[[:space:]]*//' -e 's/DNS://g' -e 's/,//g' | \
        sort)

    echo "|   domains in current certificate:"
    IFS=' ' read -r -a array <<< "${ca_domains}" ; unset IFS
    IFS=$'\n' CURRENT_CERTIFICATES=($(sort <<<"${array[*]}"))  ; unset IFS

    for d in ${CURRENT_CERTIFICATES[@]}
    do
      echo "|    - ${d}"
    done
  fi
}

diff_arrays() {

  if [ ! "${#CERTBOT_DOMAINS[@]}" -eq "${#CURRENT_CERTIFICATES[@]}" ]
  then
    CERTBOT_EXPAND=true

    echo "|   you must expand your certifiacte!"

    a=" $(printf '%s ' ${CERTBOT_DOMAINS[@]})" # Watch the space at the start!!.
    for i in "${CURRENT_CERTIFICATES[@]}"
    do
      a=${a/ "$i" / };
    done

    echo "|   these are new domains:"
    for d in ${a[@]}
    do
      echo "|    - ${d}"
    done
  else
    CERTBOT_EXPAND=false
  fi
}

cert_enddate() {

  enddate=$(openssl x509 \
      -enddate \
      -noout \
      -in ${1} | cut -d'=' -f2)
  exp=$(date -d "${enddate}" +%s)

  echo "${exp}"
}

file_age() {
  FILE_CREATED_TIME=$(date -r "${1}" +%s)
  TIME_NOW=$(date +%s)
  echo "$[ ${TIME_NOW} - ${FILE_CREATED_TIME} ]"
}

test_running_webserver() {

  running_webserver=$(ss -ant | awk '$1 == "LISTEN" && $4 ~ /[^0-9]80$/' | wc -l)

  if [ ${running_webserver} -eq 0 ]
  then
    echo "no running webserver found."
    exit 1
  fi
}

test_well_known() {

  local error=

  for d in ${CERTBOT_DOMAINS[@]}
  do
    uuid=$(uuidgen --random) # tr -cd '[:alnum:]' < /dev/urandom | fold -w42 | head -n1)
    touch "${CERTBOT_ACME_DIR}/.well-known/acme-challenge/${uuid}"

    set +e
    RESULT_STATUS=$(curl \
      --silent \
      --location \
      --head \
      --output /dev/null \
      --write-out "%{http_code}" \
      "http://${d}/.well-known/acme-challenge/${uuid}")

    printf "|   %-32s with status code: %s\n" "${d}" "${RESULT_STATUS}"

    if [ ! "${RESULT_STATUS}" -eq "200" ]
    then
      error=true
    fi

    rm --force "${CERTBOT_ACME_DIR}/.well-known/acme-challenge/${uuid}"
  done

  set -e

  if [ ! "${error}" = "true" ]
  then
    echo "|   All domains are functional"
  else
    echo "|   An error occurred during the check!"
  fi
}

build_domain_string() {

  declare -a args=()
  for i in "${CERTBOT_DOMAINS[@]}"
  do
      args+=("--domain $i")
  done

  DOMAINS=$(printf "%s "  "${args[@]}")

  echo "${DOMAINS}"
}

renew_certificates() {

  local domain="${1}"
  local certbot_opts="${2}"
  local domains="${3}"
  local CERTBOT_CERT_FILE=$(define_cert_file ${domain})

  current_file_age=$(file_age ${CERTBOT_CERT_FILE})

  # echo "certbot ${certbot_opts} ${domains}"

  error_logfile="${TEMP_DIRECTORY}/${domain}.err"
  logfile="${TEMP_DIRECTORY}/${domain}.log"

  set +e
  result=$(certbot certonly \
    ${certbot_opts} \
    ${domains} 2> ${error_logfile} 1> ${logfile})

  result_code="${?}"

  if [ "${result_code}" -gt 0 ]
  then
    echo "|   An error occurred when calling the certbot:"
    while read -r line
    do
      echo -e "|       $line"
    done < <(cat "${error_logfile}")

    echo "|"

    while read -r line
    do
      echo -e "|       $line"
    done < <(cat "${logfile}")

  fi

  set -e

  new_file_age=$(file_age ${CERTBOT_CERT_FILE})

  set +e

  ((diff = ${new_file_age} - ${current_file_age}))

  set -e

  if [ ${diff} -lt 0 ]
  then
    echo "|   update successful."
    CERTBOT_RELOAD_WEBSERVICE=true
    # echo "|   reload nginx"
    # nginx -t
    # nginx -s reload
  fi
}

check_renew_certificates() {

  local domain="${1}"
  local CERTBOT_CERT_FILE=$(define_cert_file ${domain})

  if [ -f "${CERTBOT_CERT_FILE}" ]
  then
    DOMAINS=$(build_domain_string)

    CERTBOT_OPTS=$(define_certbot_opts "${domain}")

    exp=$(cert_enddate ${CERTBOT_CERT_FILE})
    # what is now?
    datenow=$(date -d "now" +%s)

    # how many days until CA expires?
    CERT_EXPIRE_DAYS=$(echo \( ${exp} - ${datenow} \) / 86400 | bc)

    echo "|   Checking expiration date for ${domain} ..."

    if [[ "${CERT_EXPIRE_DAYS}" -gt "${CERTBOT_EXPIRE_DAYS_LIMIT}" ]] && [[ "${CERTBOT_EXPAND}" = "false" ]]
    then
      echo "|   nothing to do, cert is up to day. renewal in ${CERT_EXPIRE_DAYS} days."
      return
    fi

    if [[ "${CERT_EXPIRE_DAYS}" -gt "${CERTBOT_EXPIRE_DAYS_LIMIT}" ]] && [[ "${CERTBOT_EXPAND}" = "true" ]]
    then
      echo "|   certificate must be expand."
      CERTBOT_OPTS=$(define_certbot_opts "${domain}" "--expand")
    else
      echo "|   will try to renew cert for ${CERTBOT_CERT_NAME}"
    fi

    renew_certificates "${domain}" "${CERTBOT_OPTS}" "${DOMAINS}"
  else
    echo "|   missing certfile: ${CERTBOT_CERT_FILE}"
  fi
}

reload_webserver() {

  if [ ${CERTBOT_RELOAD_WEBSERVICE} = "true" ]
  then
    echo "reload nginx"
    nginx -t
    nginx -s reload
  fi
}

run() {
  echo ""
  # current_certificates

  test_running_webserver

  echo "validate .well-known/acme-challenge ..."

  for domain in ${CERTBOT_DOMAINS[@]}
  do
    echo ",----------------------------------------------------------"
    echo "| acme-challenge for: ${domain}"

    if [ -f "/etc/certbot/domains/${domain}" ]
    then
      . "/etc/certbot/domains/${domain}"
      test_well_known
    fi
    echo "\`----------------------------------------------------------"
    echo ""
  done

  echo "renew letsencrypt certificates ..."

  # reload main config
  . /etc/certbot/renew.rc

  for domain in ${CERTBOT_DOMAINS[@]}
  do
    echo ",----------------------------------------------------------"
    echo "| certificate information for: ${domain}"

    if [ -f "/etc/certbot/domains/${domain}" ]
    then
      . "/etc/certbot/domains/${domain}"
      letsencrypt_certificates "${domain}"

      diff_arrays

      check_renew_certificates "${domain}"
    fi
    echo "\`----------------------------------------------------------"
    echo ""
  done

  reload_webserver

  echo ""
  echo "done."

}

run
