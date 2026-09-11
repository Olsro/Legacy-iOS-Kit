/* SPDX-License-Identifier: GPL-3.0-or-later
 * Host-only compressed HFS file insertion, using the kit's xpwn library. */
#include <hfs/hfsplus.h>
#include <hfs/hfscompress.h>
#include <hfs/hfslib.h>
#include <sys/stat.h>
#include <zlib.h>
#include <errno.h>

char endianness;
int olsn0w_compress(Bytef *out, uLongf *length, const Bytef *in, uLong size) {
    int result = compress2(out, length, in, size, Z_BEST_COMPRESSION);
    if (result == Z_OK && *length >= size + 1) {
        memmove(out + 1, in, size);
        out[0] = 0xff;
        *length = size + 1;
    }
    return result;
}
static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}
/* Linux newfs_hfs can leave the HFSX root's folder-count flag unset.
 * Older iOS fsck requires both that flag and the direct subfolder count. */
static int normalize_root(const char *path) {
    struct stat st;
    if (lstat(path, &st) || !S_ISREG(st.st_mode)) fail("Expected a regular image");
    io_func *image = openFlatFile(path);
    if (!image) fail("Cannot open image");
    Volume *volume = openVolume(image);
    if (!volume || (uint64_t)volume->volumeHeader->blockSize * volume->volumeHeader->totalBlocks != (uint64_t)st.st_size)
        fail("Invalid volume geometry");
    HFSPlusCatalogFolder *root = (HFSPlusCatalogFolder *)getRecordFromPath("/", volume, NULL, NULL);
    if (!root || root->recordType != kHFSPlusFolderRecord) fail("Missing root folder");
    CatalogRecordList *list = getFolderContents(root->folderID, volume);
    uint32_t count = 0;
    for (CatalogRecordList *item = list; item; item = item->next)
        if (item->record->recordType == kHFSPlusFolderRecord) count++;
    releaseCatalogRecordList(list);
    root->flags |= kHFSHasFolderCountMask;
    root->folderCount = count;
    root->permissions.fileMode = S_IFDIR | 0755;
    root->permissions.ownerID = root->permissions.groupID = 0;
    if (!updateCatalog(volume, (HFSPlusCatalogRecord *)root) || !updateVolume(volume)) fail("Root metadata update failed");
    free(root); closeVolume(volume); CLOSE(image);
    return 0;
}
/* xpwn's same-directory move can leave valence one too large. Recount the
 * directly affected directory from its catalog after the controlled edit. */
static int recount_directory(const char *path, const char *directory) {
    struct stat st;
    if (lstat(path, &st) || !S_ISREG(st.st_mode)) fail("Expected a regular image");
    io_func *image = openFlatFile(path);
    if (!image) fail("Cannot open image");
    Volume *volume = openVolume(image);
    if (!volume) fail("Cannot open volume");
    HFSPlusCatalogFolder *folder = (HFSPlusCatalogFolder *)getRecordFromPath(directory, volume, NULL, NULL);
    if (!folder || folder->recordType != kHFSPlusFolderRecord) fail("Missing directory");
    CatalogRecordList *list = getFolderContents(folder->folderID, volume);
    uint32_t entries = 0, folders = 0;
    for (CatalogRecordList *item = list; item; item = item->next) {
        if (item->record->recordType == kHFSPlusFolderRecord) { entries++; folders++; }
        else if (item->record->recordType == kHFSPlusFileRecord) entries++;
        else fail("Unexpected directory catalog record");
    }
    releaseCatalogRecordList(list);
    folder->valence = entries;
    if (folder->flags & kHFSHasFolderCountMask) folder->folderCount = folders;
    if (!updateCatalog(volume, (HFSPlusCatalogRecord *)folder) || !updateVolume(volume))
        fail("Directory count update failed");
    free(folder); closeVolume(volume); CLOSE(image);
    return 0;
}
static void require_metadata_only(Volume *volume, uint32_t folder, unsigned depth,
                                  uint32_t journal, uint32_t journal_info) {
    if (depth > 64) fail("Data catalog nesting exceeds initialization limit");
    CatalogRecordList *list = getFolderContents(folder, volume);
    for (CatalogRecordList *item = list; item; item = item->next) {
        if (item->record->recordType == kHFSPlusFolderRecord) {
            require_metadata_only(volume, ((HFSPlusCatalogFolder *)item->record)->folderID,
                                  depth + 1, journal, journal_info);
        } else if (item->record->recordType == kHFSPlusFileRecord) {
            HFSPlusCatalogFile *file = (HFSPlusCatalogFile *)item->record;
            if (S_ISREG(file->permissions.fileMode) && file->fileID != journal && file->fileID != journal_info)
                fail("Protection initialization requires Data without regular payload files");
        }
    }
    releaseCatalogRecordList(list);
}
static int initialize_protection_v4(const char *path) {
    struct stat st;
    if (lstat(path, &st) || !S_ISREG(st.st_mode)) fail("Expected a regular image");
    io_func *image = openFlatFile(path);
    if (!image) fail("Cannot open image");
    Volume *volume = openVolume(image);
    if (!volume || (uint64_t)volume->volumeHeader->blockSize * volume->volumeHeader->totalBlocks != (uint64_t)st.st_size ||
        !volume->attrTree || volume->attrTree->headerRec->leafRecords != 0)
        fail("Protection initialization requires a fresh attributes tree");
    HFSPlusCatalogFile *journal = (HFSPlusCatalogFile *)getRecordFromPath("/.journal", volume, NULL, NULL);
    HFSPlusCatalogFile *info = (HFSPlusCatalogFile *)getRecordFromPath("/.journal_info_block", volume, NULL, NULL);
    if (!journal || !info || journal->recordType != kHFSPlusFileRecord || info->recordType != kHFSPlusFileRecord)
        fail("Expected native journaled Data format");
    require_metadata_only(volume, kHFSRootFolderID, 0, journal->fileID, info->fileID);
    /* Apple's cp_root_xattr is little endian and belongs to CNID 1, not the
     * root directory (CNID 2). Version 4 is the iOS 6/7 protection format.
     * This supplies format metadata only; the target creates all file keys. */
    uint8_t value[28] = {4, 0};
    if (!setAttribute(volume, 1, "com.apple.system.cprotect", value, sizeof(value)) || !updateVolume(volume))
        fail("Cannot initialize protection version");
    uint8_t *readback = NULL;
    size_t length = getAttribute(volume, 1, "com.apple.system.cprotect", &readback);
    if (length != sizeof(value) || !readback || memcmp(readback, value, sizeof(value)))
        fail("Protection version readback differs");
    free(readback); free(journal); free(info);
    closeVolume(volume); CLOSE(image);
    return 0;
}
int main(int argc, char **argv) {
    struct stat image_stat, input_stat;
    uint32_t order = 1;
    endianness = *(uint8_t *)&order ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
    if (argc == 4 && !strcmp(argv[2], "--recount-directory"))
        return recount_directory(argv[1], argv[3]);
    if (argc == 5 && !strcmp(argv[2], "--replace-regular")) {
        if (lstat(argv[1], &image_stat) || !S_ISREG(image_stat.st_mode) ||
            lstat(argv[3], &input_stat) || !S_ISREG(input_stat.st_mode) ||
            (image_stat.st_dev == input_stat.st_dev && image_stat.st_ino == input_stat.st_ino))
            fail("Expected separate regular image and input files");
        io_func *image = openFlatFile(argv[1]);
        if (!image) fail("Cannot open image");
        Volume *volume = openVolume(image);
        if (!volume) fail("Cannot open volume");
        HFSPlusCatalogFile *file = (HFSPlusCatalogFile *)getRecordFromPath3(
            argv[4], volume, NULL, NULL, TRUE, FALSE, kHFSRootFolderID);
        if (!file || file->recordType != kHFSPlusFileRecord ||
            (file->permissions.fileMode & S_IFMT) != S_IFREG ||
            (file->permissions.ownerFlags & UF_COMPRESSED) || file->resourceFork.logicalSize)
            fail("Replacement requires an ordinary uncompressed file");
        FILE *source = fopen(argv[3], "rb");
        if (!source) fail("Cannot open replacement");
        AbstractFile *input = createAbstractFileFromFile(source);
        writeToHFSFile(file, input, volume);
        input->close(input);
        if (!updateVolume(volume)) fail("Replacement update failed");
        free(file); closeVolume(volume); CLOSE(image);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[2], "--normalize-root")) return normalize_root(argv[1]);
    if (argc == 3 && !strcmp(argv[2], "--initialize-protection-v4")) return initialize_protection_v4(argv[1]);
    if (argc == 4 && !strcmp(argv[2], "--untar")) {
        if (lstat(argv[1], &image_stat) || !S_ISREG(image_stat.st_mode) ||
            lstat(argv[3], &input_stat) || !S_ISREG(input_stat.st_mode) ||
            input_stat.st_size < 1024 || input_stat.st_size % 512 ||
            (image_stat.st_dev == input_stat.st_dev && image_stat.st_ino == input_stat.st_ino))
            fail("Expected separate regular image and tar files");
        io_func *image = openFlatFile(argv[1]);
        if (!image) fail("Cannot open image");
        Volume *volume = openVolume(image);
        if (!volume || (uint64_t)volume->volumeHeader->blockSize * volume->volumeHeader->totalBlocks != (uint64_t)image_stat.st_size)
            fail("Invalid volume geometry");
        FILE *input = fopen(argv[3], "rb");
        if (!input) fail("Cannot open tar");
        AbstractFile *archive = createAbstractFileFromFile(input);
        if (!archive) fail("Cannot read tar");
        hfs_untar(volume, archive);
        archive->close(archive);
        closeVolume(volume); CLOSE(image);
        return 0;
    }
    if (argc != 4) fail("Usage: hfscompress IMAGE INPUT /NEW/PATH");
    if (lstat(argv[1], &image_stat) || !S_ISREG(image_stat.st_mode) ||
        stat(argv[2], &input_stat) || !S_ISREG(input_stat.st_mode) ||
        input_stat.st_size <= 0 || input_stat.st_size > 512LL*1024*1024)
        fail("Expected a regular image and a nonempty input of at most 512 MiB");
    if (image_stat.st_dev == input_stat.st_dev && image_stat.st_ino == input_stat.st_ino)
        fail("Image and input must differ");
    if (argv[3][0] != '/' || strstr(argv[3], "//") || strstr(argv[3], "/../") ||
        strstr(argv[3], "/./") || !strcmp(argv[3], "/") ||
        !strcmp(strrchr(argv[3], '/'), "/..") || !strcmp(strrchr(argv[3], '/'), "/.") ||
        argv[3][strlen(argv[3])-1] == '/') fail("Expected an absolute file path");
    FILE *input = fopen(argv[2], "rb");
    if (!input) fail("Cannot open input");
    io_func *image = openFlatFile(argv[1]);
    if (!image) fail("Cannot open image");
    Volume *volume = openVolume(image);
    if (!volume) fail("Cannot open HFS volume");
    if ((uint64_t)volume->volumeHeader->blockSize * volume->volumeHeader->totalBlocks !=
        (uint64_t)image_stat.st_size) fail("Image must match volume geometry");
    if (!volume->attrTree) fail("Volume lacks an attributes B-tree");
    HFSPlusCatalogRecord *existing = getRecordFromPath(argv[3], volume, NULL, NULL);
    if (existing) fail("Destination already exists");
    if (!newFile(argv[3], volume)) fail("Cannot create destination");
    HFSPlusCatalogFile *file = (HFSPlusCatalogFile *)getRecordFromPath(argv[3], volume, NULL, NULL);
    if (!file || file->recordType != kHFSPlusFileRecord) fail("Destination is not a file");
    io_func *compressed = openHFSPlusCompressed(volume, file);
    if (!compressed) fail("Cannot create compression stream");
    unsigned char buffer[65536];
    off_t offset = 0;
    while (offset < input_stat.st_size) {
        size_t size = (input_stat.st_size-offset > sizeof(buffer)) ? sizeof(buffer) : input_stat.st_size-offset;
        if (fread(buffer, 1, size, input) != size || !WRITE(compressed, offset, size, buffer))
            fail("Failed to read or insert data");
        offset += size;
    }
    if (fgetc(input) != EOF || ferror(input)) fail("Input changed while reading");
    fclose(input);
    CLOSE(compressed);
    file->permissions.ownerFlags |= UF_COMPRESSED;
    file->flags |= kHFSHasAttributesMask;
    file->permissions.ownerID = 0;
    file->permissions.groupID = 0;
    file->permissions.fileMode = S_IFREG | 0644;
    if (!updateCatalog(volume, (HFSPlusCatalogRecord*)file) || !updateVolume(volume))
        fail("Failed to update metadata");
    free(file);
    closeVolume(volume);
    CLOSE(image);
    return 0;
}
