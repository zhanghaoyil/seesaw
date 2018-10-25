import os
import struct
from .utils import DictWrapper

NETLINK_CONNECTOR = 11

NLMSG_NOOP = 0x1     # Nothing
NLMSG_ERROR = 0x2    # Error
NLMSG_DONE = 0x3     # End of a dump
NLMSG_OVERRUN = 0x4  # Data lost

# struct nlmsghdr
# {
#       __u32           nlmsg_len;      /* Length of message including header */
#       __u16           nlmsg_type;     /* Message content */
#       __u16           nlmsg_flags;    /* Additional flags */
#       __u32           nlmsg_seq;      /* Sequence number */
#       __u32           nlmsg_pid;      /* Sending process port ID */
# };

nlmsghdr = struct.Struct("=I2H2I")

def netlink_pack(_type, flags, msg):
    """
    Put a netlink header on a message.
    The msg parameter is assumed to be a pre-struct-packed data block.

    We don't care about seq for now.
    """
    _len = len(msg) + nlmsghdr.size
    seq = 0
    return nlmsghdr.pack(_len, _type, flags, seq, os.getpid()) + msg

def unpack_hdr(data):
    return DictWrapper(
        zip(("len", "type", "flags", "seq", "pid"),
            nlmsghdr.unpack(data[:nlmsghdr.size])))
