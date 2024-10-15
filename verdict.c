#include <net/sock.h>

struct sock_key {
  u64 cookie;
};

// BCC seems to struggle with using BPF_SOCKMAP instead of BPF_SOCKHASH, but it's a little unclear
// whether the integer keys for SOCKMAP can be 64-bits wide anyway.
BPF_SOCKHASH(my_hash, struct sock_key, 65535);

int verdict(struct __sk_buff *skb) {
  struct sock_key skk = {
    .cookie = bpf_get_socket_cookie(skb),
  };
  int ret = my_hash.sk_redirect_hash(skb, &skk, 0);//BPF_F_INGRESS);
  if (ret != SK_PASS) {
    bpf_trace_printk("fail (%d) redirect port %d --> %d", ret, skb->local_port, bpf_ntohl(skb->remote_port));
  } else {
    bpf_trace_printk("redirect port %d --> %d", skb->local_port, bpf_ntohl(skb->remote_port));
  }
  return ret;
}
