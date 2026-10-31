/*
 * rndisd - userspace RNDIS (Android USB tethering) host for macOS.
 *
 * macOS has no RNDIS driver. This daemon:
 *   1. Watches USB for devices that expose an RNDIS interface pair
 *      (Android phones with "USB tethering" on).
 *   2. Claims them through libusb and does the RNDIS handshake.
 *   3. Creates a feth pair (fake ethernet), and shuttles Ethernet frames
 *      between the phone and the feth peer through /dev/bpf.
 *   4. Runs DHCP on the other feth end, so macOS gets an IP and gateway.
 *
 * It deliberately ignores anything that isn't RNDIS (iPhones, phones in
 * NCM/ECM mode, keyboards, ...), so macOS's native drivers keep handling those.
 *
 * Must run as root (BPF, ifconfig, ipconfig). Build: see Makefile.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libusb.h>

#ifdef __APPLE__
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define APPLE_VID 0x05AC

/* RNDIS message types */
#define RNDIS_PACKET_MSG        0x00000001u
#define RNDIS_INITIALIZE_MSG    0x00000002u
#define RNDIS_HALT_MSG          0x00000003u
#define RNDIS_QUERY_MSG         0x00000004u
#define RNDIS_SET_MSG           0x00000005u
#define RNDIS_INDICATE_STATUS   0x00000007u
#define RNDIS_KEEPALIVE_MSG     0x00000008u
#define RNDIS_CMPLT             0x80000000u

#define OID_802_3_PERMANENT_ADDRESS 0x01010101u
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010Eu
/* directed | multicast | all-multicast | broadcast | promiscuous */
#define PACKET_FILTER 0x2Fu

#define RNDIS_HDR_LEN 44
#define MAX_FRAME 1600

static int g_verbose;
static volatile sig_atomic_t g_stop;

static void rlog(const char *fmt, ...) {
    char ts[16];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}
#define DBG(...) do { if (g_verbose) rlog(__VA_ARGS__); } while (0)

static int sh(const char *fmt, ...) {
    char cmd[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    DBG("run: %s", cmd);
    int r = system(cmd);
    if (r != 0) DBG("  -> status %d", r);
    return r;
}

static inline uint32_t get32(const uint8_t *p, size_t o) {
    return (uint32_t)p[o] | ((uint32_t)p[o + 1] << 8) |
           ((uint32_t)p[o + 2] << 16) | ((uint32_t)p[o + 3] << 24);
}
static inline void put32(uint8_t *p, size_t o, uint32_t v) {
    p[o] = v; p[o + 1] = v >> 8; p[o + 2] = v >> 16; p[o + 3] = v >> 24;
}

/* ---------- device discovery ---------- */

typedef struct {
    libusb_device *dev;
    uint16_t vid, pid;
    int ctrl_if, data_if, data_alt;
    uint8_t ep_int, ep_in, ep_out;
    uint16_t out_mps;
} cand_t;

static int is_rndis_ctrl(const struct libusb_interface_descriptor *d) {
    uint8_t c = d->bInterfaceClass, s = d->bInterfaceSubClass, p = d->bInterfaceProtocol;
    return (c == 0xE0 && s == 0x01 && p == 0x03) ||  /* Wireless Controller / RNDIS (modern Android) */
           (c == 0x02 && s == 0x02 && p == 0xFF) ||  /* CDC ACM, vendor protocol (older Android) */
           (c == 0xEF && s == 0x04 && p == 0x01);    /* Misc / RNDIS over Ethernet */
}

static int find_data_iface(const struct libusb_config_descriptor *cfg, cand_t *c) {
    for (int b = 0; b < cfg->bNumInterfaces; b++) {
        const struct libusb_interface *itf = &cfg->interface[b];
        for (int a = 0; a < itf->num_altsetting; a++) {
            const struct libusb_interface_descriptor *d = &itf->altsetting[a];
            if (d->bInterfaceClass != 0x0A) continue; /* CDC Data */
            uint8_t in = 0, out = 0;
            uint16_t mps = 0;
            for (int e = 0; e < d->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ep = &d->endpoint[e];
                if ((ep->bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                if (ep->bEndpointAddress & 0x80) in = ep->bEndpointAddress;
                else { out = ep->bEndpointAddress; mps = ep->wMaxPacketSize; }
            }
            if (in && out) {
                c->data_if = d->bInterfaceNumber;
                c->data_alt = d->bAlternateSetting;
                c->ep_in = in;
                c->ep_out = out;
                c->out_mps = mps;
                return 1;
            }
        }
    }
    return 0;
}

static int find_candidate(libusb_context *ctx, cand_t *out) {
    libusb_device **list;
    ssize_t n = libusb_get_device_list(ctx, &list);
    if (n < 0) return 0;
    int found = 0;
    for (ssize_t i = 0; i < n && !found; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd)) continue;
        if (dd.idVendor == APPLE_VID) continue; /* iPhones: macOS handles these natively */
        struct libusb_config_descriptor *cfg;
        if (libusb_get_active_config_descriptor(list[i], &cfg)) continue;
        for (int a = 0; a < cfg->bNumInterfaces && !found; a++) {
            const struct libusb_interface_descriptor *id = &cfg->interface[a].altsetting[0];
            if (!is_rndis_ctrl(id)) continue;
            cand_t c;
            memset(&c, 0, sizeof c);
            c.ctrl_if = id->bInterfaceNumber;
            for (int e = 0; e < id->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ep = &id->endpoint[e];
                if ((ep->bmAttributes & 3) == LIBUSB_TRANSFER_TYPE_INTERRUPT &&
                    (ep->bEndpointAddress & 0x80))
                    c.ep_int = ep->bEndpointAddress;
            }
            if (!find_data_iface(cfg, &c)) continue;
            c.vid = dd.idVendor;
            c.pid = dd.idProduct;
            c.dev = list[i];
            libusb_ref_device(c.dev);
            *out = c;
            found = 1;
        }
        libusb_free_config_descriptor(cfg);
    }
    libusb_free_device_list(list, 1);
    return found;
}

/* ---------- session ---------- */

typedef struct {
    libusb_device_handle *h;
    int ctrl_if, data_if;
    uint8_t ep_int, ep_in, ep_out;
    uint16_t out_mps;
    uint32_t req_id, max_xfer;
    uint8_t mac[6];
    int bpf_fd;
    uint32_t bpf_len;
    char ifa[24], ifb[24];
    volatile int running;
} session_t;

static int ctrl_send(session_t *s, const uint8_t *m, int len) {
    int r = libusb_control_transfer(s->h, 0x21, 0x00, 0, s->ctrl_if,
                                    (unsigned char *)m, len, 2000);
    if (r != len) { DBG("SEND_ENCAPSULATED_COMMAND failed: %s", libusb_error_name(r)); return -1; }
    return 0;
}

static int ctrl_get(session_t *s, uint8_t *b, int blen) {
    return libusb_control_transfer(s->h, 0xA1, 0x01, 0, s->ctrl_if, b, blen, 1000);
}

/* Messages the device sends on its own (keepalive, status indications). */
static void handle_async(session_t *s, const uint8_t *m, int n) {
    if (n < 12) return;
    uint32_t type = get32(m, 0);
    if (type == RNDIS_KEEPALIVE_MSG) {
        uint8_t r[16];
        memset(r, 0, sizeof r);
        put32(r, 0, RNDIS_KEEPALIVE_MSG | RNDIS_CMPLT);
        put32(r, 4, 16);
        put32(r, 8, get32(m, 8));
        ctrl_send(s, r, 16);
    } else if (type == RNDIS_INDICATE_STATUS) {
        DBG("device status indication 0x%08x", get32(m, 8));
    }
}

static int rndis_command(session_t *s, const uint8_t *msg, int len, uint32_t reqid,
                         uint32_t cmplt, uint8_t *resp, int rlen) {
    if (ctrl_send(s, msg, len)) return -1;
    for (int i = 0; i < 250 && !g_stop; i++) {
        int n = ctrl_get(s, resp, rlen);
        if (n == LIBUSB_ERROR_NO_DEVICE) return -1;
        if (n >= 12) {
            if (get32(resp, 0) == cmplt && get32(resp, 8) == reqid) return n;
            handle_async(s, resp, n);
            continue;
        }
        usleep(20000);
    }
    return -1;
}

static int rndis_setup(session_t *s) {
    uint8_t m[64], r[1280];
    int n;
    uint32_t id;

    /* INITIALIZE */
    id = ++s->req_id;
    memset(m, 0, sizeof m);
    put32(m, 0, RNDIS_INITIALIZE_MSG); put32(m, 4, 24); put32(m, 8, id);
    put32(m, 12, 1); put32(m, 16, 0); put32(m, 20, 0x4000);
    n = rndis_command(s, m, 24, id, RNDIS_INITIALIZE_MSG | RNDIS_CMPLT, r, sizeof r);
    if (n < 52 || get32(r, 12) != 0) {
        rlog("RNDIS INITIALIZE failed (n=%d status=0x%x)", n, n >= 16 ? get32(r, 12) : 0);
        return -1;
    }
    s->max_xfer = get32(r, 36);
    rlog("RNDIS up: max_transfer=%u max_packets=%u", s->max_xfer, get32(r, 32));

    /* QUERY permanent MAC */
    id = ++s->req_id;
    memset(m, 0, sizeof m);
    put32(m, 0, RNDIS_QUERY_MSG); put32(m, 4, 28); put32(m, 8, id);
    put32(m, 12, OID_802_3_PERMANENT_ADDRESS); put32(m, 16, 0); put32(m, 20, 20);
    n = rndis_command(s, m, 28, id, RNDIS_QUERY_MSG | RNDIS_CMPLT, r, sizeof r);
    if (n < 24 || get32(r, 12) != 0) { rlog("MAC query failed"); return -1; }
    uint32_t il = get32(r, 16), io = get32(r, 20);
    if (il < 6 || (size_t)8 + io + 6 > (size_t)n) { rlog("bad MAC reply"); return -1; }
    memcpy(s->mac, r + 8 + io, 6);
    rlog("phone-side MAC %02x:%02x:%02x:%02x:%02x:%02x",
         s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5]);

    /* SET packet filter: start receiving */
    id = ++s->req_id;
    memset(m, 0, sizeof m);
    put32(m, 0, RNDIS_SET_MSG); put32(m, 4, 32); put32(m, 8, id);
    put32(m, 12, OID_GEN_CURRENT_PACKET_FILTER); put32(m, 16, 4); put32(m, 20, 20);
    put32(m, 28, PACKET_FILTER);
    n = rndis_command(s, m, 32, id, RNDIS_SET_MSG | RNDIS_CMPLT, r, sizeof r);
    if (n < 16 || get32(r, 12) != 0) { rlog("SET packet filter failed"); return -1; }
    return 0;
}

/* ---------- BPF / feth plumbing (macOS) ---------- */

#ifdef __APPLE__
static int bpf_open_if(const char *ifname, uint32_t *blen) {
    int fd = -1;
    char path[32];
    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        fd = open(path, O_RDWR);
        if (fd >= 0) break;
        if (errno != EBUSY) break;
    }
    if (fd < 0) { rlog("cannot open /dev/bpf*: %s (running as root?)", strerror(errno)); return -1; }
    uint32_t want = 1 << 19, one = 1, zero = 0;
    ioctl(fd, BIOCSBLEN, &want);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        rlog("BIOCSETIF %s: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }
    ioctl(fd, BIOCIMMEDIATE, &one);
    ioctl(fd, BIOCSHDRCMPLT, &one);   /* we supply complete Ethernet headers */
    ioctl(fd, BIOCSSEESENT, &zero);   /* don't read back what we inject */
    ioctl(fd, BIOCPROMISC);
    if (ioctl(fd, BIOCGBLEN, blen) < 0) { close(fd); return -1; }
    return fd;
}
#else
static int bpf_open_if(const char *ifname, uint32_t *blen) { (void)ifname; (void)blen; return -1; }
#endif

static void net_down(session_t *s) {
    sh("ipconfig set %s NONE >/dev/null 2>&1", s->ifa);
    sh("ifconfig %s destroy >/dev/null 2>&1", s->ifa);
    sh("ifconfig %s destroy >/dev/null 2>&1", s->ifb);
}

static int net_up(session_t *s) {
    net_down(s); /* clear leftovers from a crashed run */
    if (sh("ifconfig %s create", s->ifa) || sh("ifconfig %s create", s->ifb)) {
        rlog("could not create feth interfaces (need root; try another -u unit)");
        return -1;
    }
    sh("ifconfig %s peer %s", s->ifa, s->ifb);
    sh("ifconfig %s lladdr %02x:%02x:%02x:%02x:%02x:%02x", s->ifa,
       s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5]);
    sh("ifconfig %s up", s->ifb);
    sh("ifconfig %s up", s->ifa);
    s->bpf_fd = bpf_open_if(s->ifb, &s->bpf_len);
    return s->bpf_fd < 0 ? -1 : 0;
}

/* phone -> Mac */
static void *usb_to_bpf(void *arg) {
    session_t *s = arg;
    const size_t bufsz = 32768; /* multiple of 512/1024 bulk packet size */
    uint8_t *buf = malloc(bufsz);
    if (!buf) { s->running = 0; return NULL; }
    while (s->running && !g_stop) {
        int n = 0;
        int r = libusb_bulk_transfer(s->h, s->ep_in, buf, bufsz, &n, 1000);
        if (r == LIBUSB_ERROR_PIPE) { libusb_clear_halt(s->h, s->ep_in); continue; }
        if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
            rlog("bulk IN error: %s", libusb_error_name(r));
            s->running = 0;
            break;
        }
        size_t off = 0;
        while (off + 8 <= (size_t)n) {
            uint32_t type = get32(buf, off), len = get32(buf, off + 4);
            if (len < 8 || off + len > (size_t)n) break;
            if (type == RNDIS_PACKET_MSG && len >= RNDIS_HDR_LEN) {
                uint32_t doff = get32(buf, off + 8), dlen = get32(buf, off + 12);
                size_t start = off + 8 + doff;
                if (dlen >= 14 && start + dlen <= off + len) {
                    if (write(s->bpf_fd, buf + start, dlen) < 0)
                        DBG("bpf write: %s", strerror(errno));
                }
            }
            off += len;
        }
    }
    free(buf);
    return NULL;
}

static int send_frame(session_t *s, uint8_t *pkt, const uint8_t *fr, size_t len) {
    memset(pkt, 0, RNDIS_HDR_LEN);
    put32(pkt, 0, RNDIS_PACKET_MSG);
    put32(pkt, 4, RNDIS_HDR_LEN + len);
    put32(pkt, 8, RNDIS_HDR_LEN - 8); /* data offset is relative to byte 8 */
    put32(pkt, 12, len);
    memcpy(pkt + RNDIS_HDR_LEN, fr, len);
    int total = RNDIS_HDR_LEN + (int)len, sent = 0;
    if (s->out_mps && total % s->out_mps == 0) pkt[total++] = 0; /* avoid ZLP ambiguity */
    int r = libusb_bulk_transfer(s->h, s->ep_out, pkt, total, &sent, 2000);
    if (r == LIBUSB_ERROR_PIPE) libusb_clear_halt(s->h, s->ep_out);
    else if (r == LIBUSB_ERROR_NO_DEVICE || r == LIBUSB_ERROR_IO) { s->running = 0; return -1; }
    return 0;
}

/* Mac -> phone */
#ifdef __APPLE__
static void *bpf_to_usb(void *arg) {
    session_t *s = arg;
    uint8_t *bb = malloc(s->bpf_len);
    uint8_t *pkt = malloc(RNDIS_HDR_LEN + MAX_FRAME + 1);
    if (!bb || !pkt) { s->running = 0; free(bb); free(pkt); return NULL; }
    struct pollfd pfd = { .fd = s->bpf_fd, .events = POLLIN };
    while (s->running && !g_stop) {
        if (poll(&pfd, 1, 1000) <= 0) continue;
        ssize_t n = read(s->bpf_fd, bb, s->bpf_len);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) { rlog("bpf read: %s", strerror(errno)); s->running = 0; break; }
        size_t off = 0;
        while (off + sizeof(struct bpf_hdr) <= (size_t)n) {
            struct bpf_hdr *h = (struct bpf_hdr *)(bb + off);
            size_t cap = h->bh_caplen;
            if (off + h->bh_hdrlen + cap > (size_t)n) break;
            if (cap >= 14 && cap <= MAX_FRAME)
                send_frame(s, pkt, bb + off + h->bh_hdrlen, cap);
            off += BPF_WORDALIGN(h->bh_hdrlen + cap);
        }
    }
    free(bb);
    free(pkt);
    return NULL;
}
#else
static void *bpf_to_usb(void *arg) { (void)arg; return NULL; }
#endif

static void run_session(const cand_t *c, int unit) {
    session_t s;
    memset(&s, 0, sizeof s);
    s.ctrl_if = c->ctrl_if; s.data_if = c->data_if;
    s.ep_int = c->ep_int; s.ep_in = c->ep_in; s.ep_out = c->ep_out;
    s.out_mps = c->out_mps; s.bpf_fd = -1; s.running = 1;
    snprintf(s.ifa, sizeof s.ifa, "feth%d", unit);
    snprintf(s.ifb, sizeof s.ifb, "feth%d", unit + 1);

    int claimed_c = 0, claimed_d = 0, net = 0, threads = 0;
    pthread_t t1, t2;
    rlog("RNDIS device %04x:%04x (ctrl if %d, data if %d)", c->vid, c->pid, c->ctrl_if, c->data_if);

    int r = libusb_open(c->dev, &s.h);
    if (r) { rlog("open failed: %s", libusb_error_name(r)); return; }
    if ((r = libusb_claim_interface(s.h, s.ctrl_if))) { rlog("claim control if: %s", libusb_error_name(r)); goto out; }
    claimed_c = 1;
    if ((r = libusb_claim_interface(s.h, s.data_if))) { rlog("claim data if: %s", libusb_error_name(r)); goto out; }
    claimed_d = 1;
    r = libusb_set_interface_alt_setting(s.h, s.data_if, c->data_alt);
    if (r) DBG("set alt setting: %s (continuing)", libusb_error_name(r));

    if (rndis_setup(&s)) goto out;
    net = 1;
    if (net_up(&s)) goto out;

    pthread_create(&t1, NULL, usb_to_bpf, &s);
    pthread_create(&t2, NULL, bpf_to_usb, &s);
    threads = 1;

    sh("ipconfig set %s DHCP", s.ifa);
    rlog("link up: DHCP started on %s. Check: ifconfig %s", s.ifa, s.ifa);

    /* control loop: device notifications + periodic keepalive */
    time_t last_ka = time(NULL);
    uint8_t nb[16], rb[1280];
    while (s.running && !g_stop) {
        int got = 0, rc;
        if (s.ep_int) rc = libusb_interrupt_transfer(s.h, s.ep_int, nb, sizeof nb, &got, 1000);
        else { sleep(1); rc = LIBUSB_ERROR_TIMEOUT; }
        if (rc == LIBUSB_ERROR_NO_DEVICE || rc == LIBUSB_ERROR_IO) { rlog("device removed"); break; }
        if (rc == LIBUSB_ERROR_PIPE) libusb_clear_halt(s.h, s.ep_int);
        if (rc == 0 && got >= 8 && get32(nb, 0) == 1) {
            int n = ctrl_get(&s, rb, sizeof rb);
            if (n >= 12) handle_async(&s, rb, n);
        }
        if (time(NULL) - last_ka >= 5) {
            uint8_t k[12];
            uint32_t id = ++s.req_id;
            memset(k, 0, sizeof k);
            put32(k, 0, RNDIS_KEEPALIVE_MSG); put32(k, 4, 12); put32(k, 8, id);
            if (rndis_command(&s, k, 12, id, RNDIS_KEEPALIVE_MSG | RNDIS_CMPLT, rb, sizeof rb) < 0)
                DBG("keepalive unanswered");
            last_ka = time(NULL);
        }
    }

out:
    s.running = 0;
    if (threads) { pthread_join(t1, NULL); pthread_join(t2, NULL); }
    if (claimed_c) {
        uint8_t hlt[12];
        memset(hlt, 0, sizeof hlt);
        put32(hlt, 0, RNDIS_HALT_MSG); put32(hlt, 4, 12); put32(hlt, 8, ++s.req_id);
        ctrl_send(&s, hlt, 12);
    }
    if (s.bpf_fd >= 0) close(s.bpf_fd);
    if (net) net_down(&s);
    if (claimed_d) libusb_release_interface(s.h, s.data_if);
    if (claimed_c) libusb_release_interface(s.h, s.ctrl_if);
    libusb_close(s.h);
    rlog("session ended");
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv) {
    int unit = 40, opt;
    while ((opt = getopt(argc, argv, "u:vh")) != -1) {
        if (opt == 'u') unit = atoi(optarg);
        else if (opt == 'v') g_verbose = 1;
        else { fprintf(stderr, "usage: %s [-v] [-u feth_unit]\n", argv[0]); return opt == 'h' ? 0 : 2; }
    }
    if (geteuid() != 0) rlog("warning: not root; BPF/ifconfig will fail");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    libusb_context *ctx;
    if (libusb_init(&ctx)) { rlog("libusb_init failed"); return 1; }
    rlog("rndisd started; waiting for an RNDIS device (feth%d/feth%d)", unit, unit + 1);

    while (!g_stop) {
        cand_t c;
        if (find_candidate(ctx, &c)) {
            run_session(&c, unit);
            libusb_unref_device(c.dev);
            sleep(3); /* let the phone settle / avoid tight retry loops */
        } else {
            sleep(2);
        }
    }
    libusb_exit(ctx);
    rlog("rndisd stopped");
    return 0;
}
