#!/bin/sh

ifup() {
    /sbin/ip link add $1 type vrf table $2
    /sbin/ip link set dev $1 up
    /sbin/ip rule add oif $1 table $2
    /sbin/ip rule add iif $1 table $2

    /sbin/ip link set dev $3 master $1
    /sbin/ip link set dev $3 up
    /sbin/ip addr flush dev $3
    /sbin/ip addr add $4 dev $3
    /sbin/ip route add table $2 default via $5
}

ifup upstream 10 ens256 172.20.16.88/24 172.20.16.1
ifup grx 20 ens224 172.20.16.89/24 172.20.16.1
/sbin/ip token set ::10:00:00:59 dev ens224

exit 0
