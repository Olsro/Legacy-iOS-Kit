cmake_minimum_required(VERSION 3.10)
project(olsn0w_hfs C)
find_package(ZLIB REQUIRED)
if(NOT XPWN_SOURCE)
  message(FATAL_ERROR "XPWN_SOURCE is required")
endif()
# xpwn tries to remove an old attribute before inserting a new one. A newly
# formatted volume has no root node, and a missing key must never be removed.
file(READ "${XPWN_SOURCE}/hfs/btree.c" BTREE)
set(BEFORE "int removeFromBTree(BTree* tree, BTKey* searchKey) {")
string(FIND "${BTREE}" "${BEFORE}" POSITION)
if(POSITION EQUAL -1)
  message(FATAL_ERROR "Unexpected xpwn B-tree implementation")
endif()
string(REPLACE "${BEFORE}" "${BEFORE}\n    if (tree->headerRec->rootNode == 0) return FALSE;\n    int exact = 0;\n    BTKey *found = search(tree, searchKey, &exact, NULL, NULL);\n    free(found);\n    if (!exact) return FALSE;" BTREE "${BTREE}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/btree.c" "${BTREE}")
file(READ "${XPWN_SOURCE}/hfs/rawfile.c" RAWFILE)
set(EXTENTS_BEFORE "int writeExtents(RawFile* rawFile) {")
string(FIND "${RAWFILE}" "${EXTENTS_BEFORE}" EXTENTS_POSITION)
if(EXTENTS_POSITION EQUAL -1)
  message(FATAL_ERROR "Unexpected xpwn overflow extent writer")
endif()
string(REPLACE "${EXTENTS_BEFORE}" "int xpwn_writeExtents_unused(RawFile* rawFile) {" RAWFILE "${RAWFILE}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/rawfile.c" "${RAWFILE}")
list(APPEND SOURCES "${CMAKE_CURRENT_BINARY_DIR}/rawfile.c" extents_write.c)
set(HFS_SOURCES catalog extents xattr fastunicodecompare flatfile utility volume)
foreach(part IN LISTS HFS_SOURCES)
  list(APPEND SOURCES "${XPWN_SOURCE}/hfs/${part}.c")
endforeach()
# chmodFile/chownFile follow symlinks. Applying a tar link's metadata through
# them changes its target (for example, a 0644 /bin/sh link disables bash).
file(READ "${XPWN_SOURCE}/hfs/hfslib.c" HFSLIB)
set(LINK_BEFORE "        chmodFile(fileName, mode, volume);\n        chownFile(fileName, uid, gid, volume);")
string(FIND "${HFSLIB}" "${LINK_BEFORE}" LINK_POSITION)
if(LINK_POSITION EQUAL -1)
  message(FATAL_ERROR "Unexpected xpwn tar metadata implementation")
endif()
set(LINK_AFTER [=[        if (type == 2) {
            HFSPlusCatalogFile *link = (HFSPlusCatalogFile *)getRecordFromPath3(fileName, volume, NULL, NULL, TRUE, FALSE, kHFSRootFolderID);
            if (!link || link->recordType != kHFSPlusFileRecord) abort();
            link->permissions.fileMode = 0120000 | mode;
            link->permissions.ownerID = uid;
            link->permissions.groupID = gid;
            if (!updateCatalog(volume, (HFSPlusCatalogRecord *)link)) abort();
            free(link);
        } else {
            chmodFile(fileName, mode, volume);
            chownFile(fileName, uid, gid, volume);
        }]=])
string(REPLACE "${LINK_BEFORE}" "${LINK_AFTER}" HFSLIB "${HFSLIB}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/hfslib.c" "${HFSLIB}")
list(APPEND SOURCES "${CMAKE_CURRENT_BINARY_DIR}/hfslib.c")
# Use the resource-fork form uniformly, including small files. This avoids
# xpwn's inline attribute padding.
file(READ "${XPWN_SOURCE}/hfs/hfscompress.c" COMPRESSION)
string(REPLACE "if(numBlocks <= 1 &&" "if(0 && numBlocks <= 1 &&" COMPRESSION "${COMPRESSION}")
# The resource reference is a big-endian ID (1), name offset (0xffff),
# and four zero attribute/data-offset bytes. xpwn packs these eight bytes
# through a little-endian uint64_t, but its constant is shifted by one byte.
# Its own decompressor ignores the map; Apple's kernel validates it.
set(MAP_BEFORE "end.size = 0xFFFF01;")
string(FIND "${COMPRESSION}" "${MAP_BEFORE}" MAP_POSITION)
if(MAP_POSITION EQUAL -1)
  message(FATAL_ERROR "Unexpected xpwn compressed resource map")
endif()
string(REPLACE "${MAP_BEFORE}" "end.size = 0xFFFF0100;" COMPRESSION "${COMPRESSION}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/hfscompress.c" "${COMPRESSION}")
add_executable(olsn0w-hfscompress "${CMAKE_CURRENT_BINARY_DIR}/hfscompress.c" compress.c "${CMAKE_CURRENT_BINARY_DIR}/btree.c" ${SOURCES} "${XPWN_SOURCE}/common/abstractfile.c" "${XPWN_SOURCE}/common/base64.c")
target_include_directories(olsn0w-hfscompress PRIVATE "${XPWN_SOURCE}/include")
target_compile_definitions(olsn0w-hfscompress PRIVATE compress=olsn0w_compress _FILE_OFFSET_BITS=64)
target_link_libraries(olsn0w-hfscompress PRIVATE ZLIB::ZLIB)
