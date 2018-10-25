import struct

from .utils import DictWrapper

CN_IDX_PROC = 0x1
CN_VAL_PROC = 0x1

# struct cb_id {
#       __u32 idx;
#       __u32 val;
# };

# struct cn_msg {
#       struct cb_id id;

#       __u32 seq;
#       __u32 ack;

#       __u16 len;              /* Length of the following data */
#       __u16 flags;
#       __u8 data[0];
# };

# The data member is left out of this declaration since it may be of
# varying length. This means that unpacking of a complete message will
# have to be incremental and done solely by the decoder of the
# innermost data (in my case pec_decode() in pec.py).

cn_msg = struct.Struct("=4I2H")

def pack_msg(cb_idx, cb_val, flags, data):
    """
    Pack a cn_msg struct with the passed in data.
    The data parameter is assumed to be a pre-struct-packed data block.

    We don't care about seq or ack for now.
    """
    seq = ack = 0
    _len = len(data)
    return cn_msg.pack(cb_idx, cb_val, seq, ack, _len, flags) + data

def unpack_msg(data):
    """
    Peel off netlink header and extract the message (including payload)
    from data. This will return a DictWrapper object.
    """
    data = data[:cn_msg.size]  # Slice off trailing data
    return DictWrapper(
        zip(("cb_idx", "cb_val", "seq", "ack", "len", "flags"),
            cn_msg.unpack(data)))

