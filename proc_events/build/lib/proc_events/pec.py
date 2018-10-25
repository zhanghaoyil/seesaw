import os
import errno
import socket
import struct
from select import select

from .utils import DictWrapper
from . import netlink, connector

PROC_CN_MCAST_LISTEN = 0x1
PROC_CN_MCAST_IGNORE = 0x2

PROC_EVENT_NONE = 0x00000000
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_UID = 0x00000004
PROC_EVENT_GID = 0x00000040
PROC_EVENT_SID  = 0x00000080
PROC_EVENT_PTRACE = 0x00000100
PROC_EVENT_COMM = 0x00000200
PROC_EVENT_EXIT = 0x80000000

process_events = {"PROC_EVENT_NONE": PROC_EVENT_NONE,
                  "PROC_EVENT_FORK": PROC_EVENT_FORK,
                  "PROC_EVENT_EXEC": PROC_EVENT_EXEC,
                  "PROC_EVENT_UID": PROC_EVENT_UID,
                  "PROC_EVENT_GID": PROC_EVENT_GID,
                  "PROC_EVENT_SID": PROC_EVENT_SID,
                  "PROC_EVENT_PTRACE": PROC_EVENT_PTRACE,
                  "PROC_EVENT_COMM": PROC_EVENT_COMM,
                  "PROC_EVENT_EXIT": PROC_EVENT_EXIT}

process_events_rev = dict(zip(process_events.values(),
                              process_events.keys()))

base_proc_event = struct.Struct("=2IL")

event_struct_map = {PROC_EVENT_NONE: struct.Struct("=I"),
                    PROC_EVENT_FORK: struct.Struct("=4I"),
                    PROC_EVENT_EXEC: struct.Struct("=2I"),
                    PROC_EVENT_UID: struct.Struct("=4I"),
                    PROC_EVENT_GID: struct.Struct("=4I"),
                    PROC_EVENT_SID: struct.Struct("=2I"),
                    PROC_EVENT_PTRACE: struct.Struct("=4I"),
                    PROC_EVENT_COMM: struct.Struct("=2I16s"),
                    PROC_EVENT_EXIT: struct.Struct("=4I")}

process_list = []

def pec_bind(s):
    """
    Bind a socket to the Process Event Connector.
    This will pass on any socket.error exception raised. The most
    common one will be EPERM since you need root privileges to
    bind to the connector.
    """
    s.bind((os.getpid(), connector.CN_IDX_PROC))

def pec_control(s, listen=False):
    """
    Notify PEC if we want event notifications on this socket or not.
    """
    pec_ctrl_data = struct.Struct("=I")
    if listen:
        action = PROC_CN_MCAST_LISTEN
    else:
        action = PROC_CN_MCAST_IGNORE

    nl_msg = netlink.netlink_pack(
        netlink.NLMSG_DONE, 0, connector.pack_msg(
        connector.CN_IDX_PROC, connector.CN_VAL_PROC, 0,
        pec_ctrl_data.pack(action)))
    s.send(nl_msg)


def pec_unpack(data):
    """
    Peel off the wrapping layers from the data. This will return
    a DictWrapper object.
    """
    nl_hdr = netlink.unpack_hdr(data)
    if nl_hdr.type != netlink.NLMSG_DONE:
        # Ignore all other types of messages
        return
    # Slice off header data and trailing data (if any)
    data = data[netlink.nlmsghdr.size:nl_hdr.len]
    #msg = connector.unpack_msg(data)
    # .. and away goes the connector_message, leaving just the payload
    data = data[connector.cn_msg.size:]
    event = list(base_proc_event.unpack(data[:base_proc_event.size]))
    ev_data_struct = event_struct_map.get(event[0])
    event_data = ev_data_struct.unpack(
        data[base_proc_event.size:base_proc_event.size+ev_data_struct.size])

    fields = ["what", "cpu", "timestamp_ns"]
    if event[0] == PROC_EVENT_NONE:
        fields.append("err")
        event[1] = -1
    elif event[0] == PROC_EVENT_FORK:
        fields += ["parent_pid", "parent_tgid", "child_pid", "child_tgid"]
    elif event[0] == PROC_EVENT_EXEC:
        fields += ["process_pid", "process_tgid"]
    elif event[0] == PROC_EVENT_UID:
        fields += ["process_pid", "process_tgid", "ruid", "rgid"]
    elif event[0] == PROC_EVENT_GID:
        fields += ["process_pid", "process_tgid", "euid", "egid"]
    elif event[0] == PROC_EVENT_SID:
        fields += ["process_pid", "process_tgid"]
    elif event[0] == PROC_EVENT_PTRACE:
        fields += ["process_pid", "process_tgid", "tracer_pid", "tracer_tgid"]
    elif event[0] == PROC_EVENT_COMM:
        fields += ["process_pid", "process_tgid", "comm"]
    elif event[0] == PROC_EVENT_EXIT:
        fields += ["process_pid", "process_tgid", "exit_code", "exit_signal"]

    return DictWrapper(zip(fields, tuple(event) + event_data))

def register_process(pid=None, process_name=None, events=(), action=None):
    """
    Register a callback for processes of a specific name or
    by pid. pec_loop() will call this callback for any processes
    matching.

    If no events is specified, all events related to
    that pid will call the callback. The action can be any callable.
    One argument will be passed to the callable, the PEC message,
    as returned by pec_unpack().
    """
    for x in events:
        if x not in process_events:
            raise Exception("No such process event: 0x%08x" % (int(x),))
    process_list.append({'pid': pid,
                         'process_name': process_name,
                         'events': events})

def pec_loop(plist=process_list):
    s = socket.socket(socket.AF_NETLINK,
                      socket.SOCK_DGRAM,
                      netlink.NETLINK_CONNECTOR)

    #  Netlink sockets are connected with pid and message group mask,
    #  message groups are for multicast protocols (like our process event
    #  connector).

    try:
        pec_bind(s)
    except socket.error, (_errno, errmsg):
        if _errno == errno.EPERM:
            raise Exception("You don't have permission to bind to the "
                            "process event connector. Try sudo.")

    pec_control(s, listen=True)

    while True:
        (readable, w, e) = select([s],[],[])
        buf = readable[0].recv(256)
        event = pec_unpack(buf)
        event["what"] = process_events_rev.get(event.what)
        yield event
