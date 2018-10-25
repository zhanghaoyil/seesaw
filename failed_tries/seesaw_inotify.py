"""
Copyright (c) Zacker
Seesaw
Defenses Reversed Shell
"""

import os
import json
import time
import re
import traceback
import pyinotify

class BashHandler(pyinotify.ProcessEvent):
    def process_IN_OPEN(self, event):
        print(event.path, event.name, event.dir, event.mask, event.maskname, event.pathname, event.wd)
        ps = fetch_all_bash(flag='bash')
        print(ps)

    def process_IN_CREATE(self, event):
        print(event.path, event.name, event.dir, event.mask, event.maskname, event.pathname, event.wd)


def fetch_all_bash(flag='bash'):
    ps = os.popen('ps -eo uid,pid,sid,comm | grep %s | awk \'{print $1,$2,$3}\'' % (flag,)).read()
    ps = [x.split(' ') for x in ps.split('\n') if x != '']
    return ps

def fetch_server_sids(flag='httpd'):
    sid = os.popen('ps -eo sid,comm | grep %s | awk \'{print $1}\' | sort -u' % (flag,)).read()
    sid = [int(x) for x in sid.split('\n') if x != '']
    return sid

def fetch_valid_users():
    users = os.popen('grep /bin/bash /etc/passwd | awk -F\':\' \'{print $3}\'').read()
    return [int(x) for x in users.split('\n') if x != '']

def check_for_reversed_shell(pid):
    fds = os.popen('lsof -p %s -Pn | grep \'\(IP\|CHR\)\' | awk \'{print $5,$9}\'' % (pid,)).read()
    fds = [x for x in fds.split('\n')]
    has_socket = has_tty = False
    peer = None
    for fd in fds:
        detail = fd.split(' ')
        if detail[0] == 'CHR' and re.findall('(tty|pts|ptmx)', detail[1]):
            has_tty = True
        elif 'IP' in detail[0]:
            has_socket = True
            peer = detail[1].split('->')[1]
    return has_socket and not has_tty, peer

def deal(pid):
    # simple and efficient kill
    os.system('kill -9 %s' % (pid,))

def alert(message):
    print(message)

if __name__ == '__main__':
    valid_users = fetch_valid_users()
    server_sids = fetch_server_sids('httpd')
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE
    notifier = pyinotify.Notifier(wm, BashHandler())
    wm.add_watch('/proc', mask, rec=False)
    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                print('detached')
                notifier.read_events()
        except KeyboardInterrupt:
            notifier.stop()
            break
    # if os.path.exists('/var/log/cmdline'):
    #     with open('/var/log/cmdline', 'r') as log_file:
    #         lines = tail_log(log_file)
    #         for line in lines:
    #             if line['uid'] in valid_users and line['sid'] not in server_sids:
    #                 continue
    #             else:
    #                 try:
    #                     positive, peer = check_for_reversed_shell(line['pid'])
    #                     if positive:
    #                         deal(line['pid'])
    #                         alert('###Reversed Shell Detached: pid:%s peer:%s. Webshell directory: %s. Killed immediately. ###' % (line['pid'], peer, line['pwd']))
    #                 except Exception as e:
    #                     traceback.print_stack(e)