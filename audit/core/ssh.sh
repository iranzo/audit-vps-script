#!/bin/bash
#
# MIT License

# Copyright (c) 2024 Kyriacos Kyriacou (@kkyrio)

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# audit.sh
#
# Author: Kyri (https://x.com/kkyrio)
#
# This script performs security checks on an Ubuntu/Debian VPS, ensuring it follows
# good security practices. It checks for:
#   * UFW firewall configuration
#   * SSH hardening
#   * Non-root user setup
#   * Automatic updates
#   * Fail2ban configuration
#
# Usage:
#   Local reporting only:
#     ./audit.sh
#
#   Report to remote service:
#     ./audit.sh <session-id>
#
# Note: Certain commands require sudo privileges.
# When no session id is provided, results are only printed to terminal.
# When session id is set, results are sent to API_ENDPOINT and also printed to terminal.
# Each check's status (running/pass/fail/error) is reported progressively in both modes.

# Load common functions
[[ -f "${RISU_BASE}/common-functions.sh" ]] && . "${RISU_BASE}/common-functions.sh"

if ! is_active sshd; then
    echo "sshd is not active" >&2
fi

if ! is_service_running sshd; then
    echo "sshd is not running" >&2
fi

# Dump SSH config
FILE=$(mktemp)
trap "rm ${FILE}" EXIT
sshd -T >${FILE}

for keyword in PermitRootLogin KbdInteractiveAuthentication PasswordAuthentication UsePAM; do
    if is_lineinfile "${keyword}.*no" ${FILE}; then
        echo "$keyword present in sshd config" >&2
    else
        echo "Expected $keyword 'no' missing in sshd config" >&2
    fi
done

# authorized_keys
exit ${RC_INFO}
