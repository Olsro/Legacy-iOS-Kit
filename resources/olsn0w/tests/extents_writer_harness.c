#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define OLSN0W_EXTENTS_TEST
#define TRUE 1
#define FALSE 0
typedef struct { uint32_t startBlock, blockCount; } HFSPlusExtentDescriptor;
typedef HFSPlusExtentDescriptor HFSPlusExtentRecord[8];
typedef struct { uint16_t keyLength; uint8_t forkType, pad; uint32_t fileID, startBlock; } HFSPlusExtentKey;
typedef HFSPlusExtentKey BTKey;
typedef struct Extent { uint32_t startBlock, blockCount; struct Extent *next; } Extent;
typedef struct { HFSPlusExtentRecord extents; } Fork;
typedef struct { void *extentsTree; } Volume;
typedef struct { Fork *forkData; Extent *extents; uint32_t id; Volume *volume; } RawFile;
static HFSPlusExtentRecord records[8];
static uint32_t keys[8];
static unsigned count;
static int remove_ok=1, insert_ok=1;
void flipExtentRecord(HFSPlusExtentRecord *record) {
    for (unsigned i=0;i<8;i++) {
        uint32_t values[2]={(*record)[i].startBlock,(*record)[i].blockCount};
        unsigned char *bytes=(unsigned char *)&(*record)[i];
        for (unsigned j=0;j<8;j++) bytes[j]=(values[j/4]>>(24-8*(j%4)))&255;
    }
}
int removeExtents(RawFile *f) { (void)f; return remove_ok; }
int addToBTree(void *tree, BTKey *key, size_t size, unsigned char *value) {
    assert(tree && size==sizeof(HFSPlusExtentRecord));
    assert(key->fileID==42 && key->forkType==0 && key->pad==0);
    assert(count<8); keys[count]=key->startBlock;
    for (unsigned i=0;i<8;i++) {
        uint32_t fields[2]={0,0};
        for (unsigned j=0;j<8;j++) fields[j/4]=(fields[j/4]<<8)|value[i*8+j];
        records[count][i]=(HFSPlusExtentDescriptor){fields[0],fields[1]};
    }
    count++; return insert_ok;
}
#include "../native/hfscompress/extents_write.c"
int main(void) {
    Fork fork; Volume volume={(void *)1}; Extent extents[25];
    RawFile file={&fork,extents,42,&volume};
    for (unsigned length=0; length<=25; length++) {
        memset(&fork,0xcc,sizeof(fork)); count=0;
        for (unsigned i=0;i<length;i++)
            extents[i]=(Extent){1000+i*100,i+1,i+1<length?&extents[i+1]:NULL};
        file.extents=length?extents:NULL;
        assert(writeExtents(&file));
        uint32_t logical=0;
        for (unsigned i=0;i<length;i++) {
            HFSPlusExtentDescriptor d;
            if (i<8) d=fork.extents[i];
            else {
                if (i%8==0) assert(keys[i/8-1]==logical);
                d=records[i/8-1][i%8];
            }
            assert(d.startBlock==extents[i].startBlock && d.blockCount==i+1);
            logical+=d.blockCount;
        }
        for (unsigned i=length;i<(length<8?8:((length+7)/8)*8);i++) {
            HFSPlusExtentDescriptor d=i<8?fork.extents[i]:records[i/8-1][i%8];
            assert(d.startBlock==0 && d.blockCount==0);
        }
    }
    remove_ok=0; count=0; assert(!writeExtents(&file) && count==0);
    remove_ok=1; insert_ok=0; assert(!writeExtents(&file));
    return 0;
}
