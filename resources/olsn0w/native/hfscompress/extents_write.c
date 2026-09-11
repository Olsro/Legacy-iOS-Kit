/* HFS overflow keys count logical file blocks, not physical disk blocks.
 * Keep xpwn's catalog extents, then emit zero-padded groups of eight. */
#ifndef OLSN0W_EXTENTS_TEST
#include <hfs/hfsplus.h>
#endif
#include <stdint.h>
#include <string.h>

int removeExtents(RawFile *file);

int writeExtents(RawFile *file) {
    if (!removeExtents(file)) return FALSE;
    memset(file->forkData->extents, 0, sizeof(HFSPlusExtentRecord));
    Extent *extent = file->extents;
    uint32_t logical = 0;
    for (unsigned i = 0; i < 8 && extent; i++, extent = extent->next) {
        file->forkData->extents[i].startBlock = extent->startBlock;
        file->forkData->extents[i].blockCount = extent->blockCount;
        logical += extent->blockCount;
    }
    HFSPlusExtentKey key;
    memset(&key, 0, sizeof(key));
    key.keyLength = sizeof(key) - sizeof(key.keyLength);
    key.fileID = file->id;
    while (extent) {
        HFSPlusExtentRecord record = {{0}};
        key.startBlock = logical;
        for (unsigned i = 0; i < 8 && extent; i++, extent = extent->next) {
            record[i].startBlock = extent->startBlock;
            record[i].blockCount = extent->blockCount;
            logical += extent->blockCount;
        }
        flipExtentRecord(&record);
        if (!addToBTree(file->volume->extentsTree, (BTKey *)&key,
                       sizeof(record), (unsigned char *)record)) return FALSE;
    }
    return TRUE;
}
