# bash completion for fettle
#
# Install (either one):
#   source /path/to/fettle/contrib/fettle.bash          # in ~/.bashrc
#   sudo ln -s "$PWD/contrib/fettle.bash" /usr/share/bash-completion/completions/fettle
#
# This script deliberately knows nothing about fettle's options. It asks fettle
# itself, so it cannot fall out of step with the CLI — which is the whole point:
# every action has three interchangeable spellings, -S/-U/-p are intercepted before
# the argument parser, and each subcommand has its own flags. Encoding that a second
# time in bash is how the two drift apart.
#
# Notes:
#   * It binds to the `fettle` command. Running `python -m fettle` gets no completion —
#     bash completes on the command name, and that one is `python`.
#   * Values are not completed, only names: paths for --config, hosts for `remote`,
#     package names for aur-precheck. That is a deliberate scope choice, not an
#     oversight. sys-audit's categories ARE completed, because they are a fixed set.
#   * Requires bash 4+ for mapfile. fettle needs no completion-specific extras.

_fettle() {
    local candidates
    # 2>/dev/null and `|| return 0`: if fettle is missing, broken, or mid-upgrade, the
    # right outcome is "no suggestions", never an error over the user's prompt.
    candidates="$(fettle --complete "$COMP_CWORD" -- "${COMP_WORDS[@]}" 2>/dev/null)" \
        || return 0
    # mapfile rather than an unquoted $(...) so a candidate is never word-split or
    # glob-expanded. fettle prints one per line for exactly this reason.
    mapfile -t COMPREPLY < <(compgen -W "${candidates}" -- "${COMP_WORDS[COMP_CWORD]}")
}

complete -F _fettle fettle
