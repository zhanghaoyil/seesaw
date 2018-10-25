from proc_events.pec import pec_loop
import subprocess
import shlex
import traceback
import re

def check_for_reversed_shell(lsof):
    '''
    if the process was bash which had got remote socket and not got tty, then it must be a reversed shell.
    :param lsof:
    :return: positive: bool
             peer: str remote socket
    '''
    fds = [x.strip() for x in lsof.split('\n') if x]
    is_bash = has_socket = has_tty = False
    peer = None
    for fd in fds:
        detail = fd.split()
        fd = detail[3]
        t = detail[4]
        if t == 'CHR' and re.findall('(tty|pts|ptmx)', detail[-1]):
            has_tty = True
        elif 'IP' in t and detail[-1] == '(ESTABLISHED)':
            has_socket = True
            peer = detail[-2].split('->')[1]
        elif 'txt' in fd and re.findall('bash', detail[-1]):
            is_bash = True
    return (is_bash and has_socket and not has_tty), peer

if __name__ == "__main__":
    self_pids = []
    for e in pec_loop():
        if e['what'] == 'PROC_EVENT_EXEC':
            try:
                #exclude lsof processes
                if e['process_tgid'] in self_pids:
                    self_pids.remove(e['process_tgid'])
                    continue
                else:
                    p = subprocess.Popen(shlex.split('lsof -p %s -Pn' % (e['process_tgid'])), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()
                    if out:
                        try:
                            positive, peer = check_for_reversed_shell(out)
                            if positive:
                                print(out)
                                print('######\n###Reversed Shell Detached: pid:%s peer:%s. Killed immediately. ###\n######' % (e['process_tgid'], peer))
                        except Exception as ex:
                            traceback.print_exc(ex)
            except Exception as ex:
                traceback.print_exc(ex)
            finally:
                #prevent self-excitation
                self_pids.append(int(p.pid))