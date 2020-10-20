#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include "data_structure.h"


void add_tmp_v4(uint32_t ip,uint32_t size,entry_v4 *item)
{
    entry_v4 *elem;
    elem = malloc(sizeof(struct entry_v4));
    if(elem){
        elem->ip=ip;
        elem->size=size;
    }
    TAILQ_INSERT_HEAD(&item->head,elem,entries);
}