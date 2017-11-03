#!/bin/bash

#
# capsh from libcap2 git master (newer that 2.25) is needed
#

cmd="rebar3 shell --setcookie secret --sname gtp-u-node --apps gtp_u_kmod"

sudo rmmod gtp
sudo capsh --caps="cap_net_admin,cap_net_raw,cap_sys_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" --keep=1 --user=$USER --addamb=cap_net_admin,cap_net_raw,cap_sys_admin -- -c "$cmd"