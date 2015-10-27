# CDP/LLDP Tool for Checkpoint Firewalls (also almost every Linux based systems)

1. Introduction
2. Quick Setup
3. Options

#Introduction

CDP/LLDP Protocol is one of the most interesting and easy ways to get all the information from the devices that are in a datacenter. This protocol could will help you to build your whole map easy, quickly and dynamically. Working for a long time with firewalls, this is one of the things that I miss more. So, I build a small tool that will allow your device to “speak” and understand CDP/LDDP protocols. The idea for this tool born from the necessity in Checkpoint Firewalls to understand CDP/LLDP protocols, helping firewall administrators to draw a map for this infrastructure.

This work is based in the excellent cdpd daemon from  Alexandre Snarskii (http://snar.spb.ru/prog/cdpd/)

#Quick Setup

Download cdpd-cp to your box and run it. It’s a crossover compiled C program over CentOS 5 with support for 32/64 bit platform.

# Options

You can see from the help:

# cdpd-cp -help
CDP/LLDP Protocol listener for Checkpoint Firewalls v1.0 (libpcap version 1.7.4)
Usage: cdpd-cp <-c | -l> [-i iface] [-m time] [-X]
At least you need to specify -c or -l
  -d      : debug mode ON
  -h      : this help message
  -i name : interface to exclude for sending cpd/lldp packets (usually sync interface)
  -t time : maximum time to wait for an incomming CDP packet (60 sec by default)
  -c      : send/listen CDP neighbors
  -l      : send/liten LLDP neighbors
  -X      : only SEND don't listen for any neighbor

