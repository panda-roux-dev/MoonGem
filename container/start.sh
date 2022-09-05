declare -a args

args=( -r /gemini/public -k /gemini/$MG_KEY_NAME -c /gemini/$MG_CERT_NAME -p $MG_PORT )

if [[ -f /gemini/$MG_BEFORE_SCRIPT ]]
then
  args=( "${args[@]}" -b /gemini/$MG_BEFORE_SCRIPT )
fi

if [[ -f /gemini/$MG_AFTER_SCRIPT ]]
then
  args=( "${args[@]}" -a /gemini/$MG_BEFORE_SCRIPT )
fi

if [[ -f /gemini/$MG_ERROR_SCRIPT ]]
then
  args=( "${args[@]}" -e /gemini/$MG_BEFORE_SCRIPT )
fi

/app/moongem "${args[@]}"
