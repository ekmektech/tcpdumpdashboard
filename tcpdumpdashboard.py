#!/usr/bin/python3
# encoding: utf-8
# Copyright (c) 2018 Maksim AbuAjamieh, Ali Saleh Baker
# @Script: tcpdumpdashboard.py
# @Author:  Maksim AbuAjamieh, Ali Saleh Baker
# @Email: eng.maksim@gmail.com, alivxlive@gmail.com
# @Description: tcpdump output dashboard


Version = """v1.0.0 - Maksim A and Ali B.
This script is GPL v3 Licensed for non profit public use
"""

import subprocess as sub
import sys
import platform
import re
import uuid
import os
import time
import operator
import datetime
import argparse
from shutil import which
from threading import Timer
from collections import defaultdict


parser = argparse.ArgumentParser(description="""Get TCPDUMP Statistics, a simple \
        tool to get a quick check for any possible unexpected traffic.
        This will monitor for "Syn, Fin, and Reset packets" and report counters for established sockets.
        Exmaple:
        python3 tcpdumpdashboard.py  -u /etc/hosts -s -l 50000 -f /tmp/output -r 10

        """)
parser.add_argument("--refresh", '-r', dest='refresh',
                    help="screen refresh rate in seconds", type=int, required=False)
parser.add_argument("--lines", '-l', dest='lines',
                    help="Maximum number of lines to print", type=int, required=False)
parser.add_argument('--keeplog', '-k', dest='keeplog', action='store_true',
                    help='keep a copy of raw TCPDUMP Traffic captured')
parser.add_argument("--tofile", '-f', dest='tofile',
                    help="Keep a copy of last stats output", type=str, required=False)
parser.add_argument('--sorted', '-s', dest='sorted',
                    action='store_true', help='Sort output by message count')
parser.add_argument("--hosts", '-u', dest='hosts',
                    help="Use a '/etc/hosts' compatible file format to resolve output", type=str, required=False)
parser.add_argument('--version', '-v', dest='version',
                    action='store_true', help='Display version information')
args = parser.parse_args()

maps = dict()
SORTED = ""
RESOLVE = False

if args.version:
    print(Version)
    sys.exit(0)

if not args.lines:
    LINES = 20
else:
    LINES = args.lines

if not args.refresh:
    REFRESH = 2
else:
    REFRESH = args.refresh

if not args.sorted:
    SORTED = "not "

if args.hosts:
    if os.path.isfile(args.hosts):
        with open(args.hosts, 'r') as f:
            for line in f.readlines():
                if line.strip():
                    if line.startswith('#'):
                        continue
                    parsed = line.split()
                    ip = parsed[0]
                    hosts = tuple(parsed[1:])
                    maps[ip] = hosts
if maps:
    RESOLVE = True

if args.keeplog:
    TEMP_FILE = os.path.join("/tmp", str(uuid.uuid4()))

counter = dict()
counter['Syn'] = defaultdict(dict)
counter['Fin'] = defaultdict(dict)
counter['Reset'] = defaultdict(dict)
counter['Reset-Ack'] = defaultdict(dict)
counter['Syn-Ack'] = defaultdict(dict)
counter['Fin-Ack'] = defaultdict(dict)

start_time = str(datetime.datetime.now())
log_threshold = 16
last_syn = 0
last_fin = 0
last_rst = 0

version = platform.python_version()
if not int(version.split('.')[0]) == 3:
    print ("Python 3 or higher required to run")
    sys.exit(1)
Failed_dep = []
for name in ["npyscreen", "tabulate"]:
    try:
        __import__(name)
    except:
        Failed_dep.append(name)
if Failed_dep:
    print ("Please make sure to install following python modules first:")
    for dep in Failed_dep:
        print(dep, end=" ")
    print()
    sys.exit(1)
if which('tcpdump') is None:
    print ("TCPDUMP is not installed, please install tcpdump then rerun")
    sys.exit(1)

# Modules outside Standard Lib

import npyscreen
from tabulate import tabulate


def main():

    p = ''
    pat = re.compile(
        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,})\s+>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,})")
    begin = re.compile("(\d{5,}\.\d{1,}).*")
    p = sub.Popen(('sudo', 'tcpdump', '-l', '-vvv', '-nnvvS', '-s 68', '-tt',
                   'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0'), stdout=sub.PIPE)
    old = ''
    try:
        for r in iter(p.stdout.readline, b''):
            if args.keeplog:
                with open(TEMP_FILE, "ab") as raw:
                    raw.write(r)
            Time = re.findall(begin, str(r))
            if Time:
                last_ts = Time
                old_line = r
                continue
            Time = last_ts
            r = old_line + r
            if b' [S.' in r:
                key = 'Syn-Ack'
            elif b' [S' in r:
                key = 'Syn'
            elif b' [F.' in r:
                key = 'Fin-Ack'
            elif b' [F' in r:
                key = 'Fin'
            elif b' [R.' in r:
                key = 'Reset-Ack'
            elif b' [R' in r:
                key = 'Reset'
            else:
                continue
            res = re.findall(pat, str(r))[0]
            s, s_port, d, d_port = res
            if RESOLVE:
                if s in maps.keys():
                    s = str(maps[s]).replace(
                        "(", '').replace(")", "").replace(",", " ")
                if d in maps.keys():
                    d = str(maps[d]).replace(
                        "(", '').replace(")", "").replace(",", " ")
            socket = "%s -> %s" % (s, d)
            if not 'LastTS' in counter[key][socket].keys():
                counter[key][socket]['LastTS'] = Time
            else:
                nTime = float(Time[0])
                if nTime > float(counter[key][socket]['LastTS'][0]):
                    counter[key][socket]['LastTS'] = Time
            if not 'packet-sum' in counter[key][socket].keys():
                counter[key][socket]['packet-sum'] = 1
            else:
                counter[key][socket]['packet-sum'] += 1
    except KeyboardInterrupt:
        sys.exit(0)


def print_info(info):
    if args.keeplog:
        temp = "Temp file location: %s" % TEMP_FILE
    else:
        temp = ""
    if args.sorted:
        Sorted = "lines printed are %ssorted by count" % SORTED
    else:
        Sorted = "lines printed are %ssorted by count - use -s to sort" % SORTED
    message = """
--------------------------------------------
Start time: %s
%s
%s
Outputing a maximum of %s lines to screen - use -l to set
Refreshing every %s seconds - use -r to set
--------------------------------------------

%s

    """ % (start_time, temp, Sorted,  LINES, REFRESH, info)
    if args.tofile:
        with open(args.tofile, 'w') as output:
            output.write(message)
    return message


def print_current_status():
    headers = ['Type', 'Socket', 'Last Time', 'Count']
    data = []
    if len(counter.keys()) > 0:
        for k, v in counter.items():
            for sk, sv in v.items():
                temp = []
                temp.append(k)
                temp.append(sk)
                for f, value in sv.items():
                    if type(value) == list:
                        value = int(float(value[0]) * 1000)
                        value = time.strftime(
                            "%a %d %b %Y %H:%M:%S GMT", time.gmtime(value / 1000.0))
                    temp.append(value)
                if ':' in str(temp[-1]):
                    temp[-1], temp[-2] = temp[-2], temp[-1]
                data.append(temp[:])
                del temp
    if args.sorted:
        data = sorted(data, key=operator.itemgetter(-1), reverse=True)[:LINES]
    else:
        data = data[:LINES]
    formatted = tabulate(data, headers=headers, tablefmt='orgtbl')
    res = print_info(formatted)
    del data
    return res


class TinyForm(npyscreen.FormBaseNew):
    DEFAULT_NEXTRELY = 0
    BLANK_LINES_BASE = 0


class draw(npyscreen.Form):
    def create(self):
        message = ""
        print ("ok")

        def print_stats():
            t = Timer(REFRESH, print_stats, [])
            t.daemon = True
            t.start()
            message = print_current_status()
            lines = message.split("\n")
            self.framed = False
            F = TinyForm(name="TCPDUMP Stats",
                         framed=False,
                         lines=len(lines),
                         columns=0,
                         minimum_lines=1)
            for line in lines:
                F.add(npyscreen.Textfield, editable=False, value=line)
            F.edit()
            F.display()
        print_stats()

    def exit_application(self):
        self.parentApp.setNextForm(None)
        self.editing = False


class display(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm('MAIN', draw, name='TCPDUMP Statistics')
        main()


if __name__ == '__main__':
    try:
        UserApp = display().run()
    except:
        print("Exiting program, Goodbye")
        sys.exit(0)
