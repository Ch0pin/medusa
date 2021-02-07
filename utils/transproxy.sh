#!/bin/sh


iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $1:$2
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $1:$2
iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE
iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE
