#include "pcap.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- pcap on-disk structures (little-endian) ---- */
typedef struct {
    uint32_t magic;          /* 0xa1b2c3d4 */
    uint16_t ver_major;      /* 2 */
    uint16_t ver_minor;      /* 4 */
    int32_t  thiszone;       /* 0 */
    uint32_t sigfigs;        /* 0 */
    uint32_t snaplen;        /* 65535 */
    uint32_t network;        /* 1 = DLT_EN10MB */
} __attribute__((packed)) PcapGlobalHdr;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed)) PcapPktHdr;

PcapWriter *pcap_writer_open(const char *path) {
    PcapWriter *pw = calloc(1, sizeof(*pw));
    if (!pw) return NULL;

    pw->fp = fopen(path, "wb");
    if (!pw->fp) { free(pw); return NULL; }

    PcapGlobalHdr gh = {
        .magic     = 0xa1b2c3d4,
        .ver_major = 2,
        .ver_minor = 4,
        .thiszone  = 0,
        .sigfigs   = 0,
        .snaplen   = 65535,
        .network   = 1,
    };
    fwrite(&gh, sizeof(gh), 1, pw->fp);
    pw->written = 0;
    return pw;
}

int pcap_writer_write(PcapWriter *pw, const uint8_t *pkt, uint32_t caplen) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    PcapPktHdr ph = {
        .ts_sec   = (uint32_t)ts.tv_sec,
        .ts_usec  = (uint32_t)(ts.tv_nsec / 1000),
        .incl_len = caplen,
        .orig_len = caplen,
    };
    if (fwrite(&ph, sizeof(ph), 1, pw->fp) != 1) return -1;
    if (fwrite(pkt, 1, caplen, pw->fp) != caplen) return -1;
    fflush(pw->fp);
    pw->written++;
    return 0;
}

void pcap_writer_close(PcapWriter *pw) {
    if (!pw) return;
    if (pw->fp) fclose(pw->fp);
    free(pw);
}
