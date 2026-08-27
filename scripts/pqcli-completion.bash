# bash completion for pqcli
_pqcli() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  local cmds="help version list-algs doctor genkey list-keys keys export import use info rm-key passwd config fingerprint backup restore keyring contacts trust untrust encrypt decrypt sign verify inspect reencrypt wipe"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
  fi
}
complete -F _pqcli pqcli
