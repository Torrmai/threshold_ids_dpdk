#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdint.h>
typedef struct entry_v4
{
    uint32_t ip;
    uint32_t size;
    TAILQ_ENTRY(entry_v4) entries;
    TAILQ_HEAD(,entry_v4) head;
}entry_v4;
struct entry_v6
{
    uint8_t ip[16];
    uint32_t size;
    TAILQ_ENTRY(entry_v6) entries;
};

void add_tmp_v4(uint32_t ip,uint32_t size,entry_v4 *item);
void add_tmp_v6(uint8_t ip[],uint32_t size);