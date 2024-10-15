"""
Accept tproxy sockets on port 8080, open corresponding MPTCP sockets, and use eBPF to pipe the data
back and forth.

Unsolved problems:

* connection cleanup
* eBPF socket map binding for MPTCP
* avoiding need to `recv(1)` on the upstream socket to unstick
"""

import atexit
from contextlib import closing
import ctypes
import logging
import os
import select
import struct
import socket
import time

from bcc import BPF, BPFAttachType, lib

logger = logging.getLogger(__name__)

SO_COOKIE = 57

prog = BPF(src_file="verdict.c")
func_verdict = prog.load_func("verdict", prog.SK_SKB)

map_fd = lib.bpf_table_fd(prog.module, b"my_hash")
prog.attach_func(func_verdict, map_fd, BPFAttachType.SK_SKB_STREAM_VERDICT)

atexit.register(lambda: prog.detach_func(func_verdict, map_fd, BPFAttachType.SK_SKB_STREAM_VERDICT))

class sock_key(ctypes.Structure):
  _fields_ = [("cookie", ctypes.c_uint64)]

def add_sock(key_sock, sock):
  # TODO: can we unpack directly into the struct?
  key = struct.unpack("Q", key_sock.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))[0]
  filenr = ctypes.c_int(sock.fileno())
  res = lib.bpf_update_elem(map_fd, ctypes.byref(sock_key(key)), ctypes.byref(filenr), 0)
  if res < 0:
    errno = ctypes.get_errno()
    errstr = os.strerror(errno)
    raise Exception(f"Could not add socket to hash: [OSError {errno}] {errstr}")

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    sock.bind(("127.0.0.1", 8080))
    sock.listen(0)

    logger.debug("listening on port 8080")

    while True:
      logger.debug("calling accept()")
      conn, addr = sock.accept()
      logger.info(f"accepted connection from {addr}")
      # TODO: make mptcp work here
      # https://github.com/multipath-tcp/mptcp_net-next/issues/521
      with conn, socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP) as downstream:
        # Thanks to `tproxy`, this connects to the original destination IP and port.
        downstream.connect(conn.getsockname())
        logger.debug("adding to map")
        add_sock(downstream, conn)
        add_sock(conn, downstream)
        logger.debug("added to map")

        # At this point, our verdict program will handle moving the data back and forth.
        # TODO: handle socket cleanup in eBPF

        # These don't seem to do what I want them to do :(
        downstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)

        # but this does?!
        try:
          assert not conn.recv(1)
        except OSError as e:
          if e.errno != 11:
            raise

        time.sleep(5)
