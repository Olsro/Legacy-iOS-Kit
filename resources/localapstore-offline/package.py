#!/usr/bin/env python3
"""Repackage the user-supplied LocalIAPStore deb with its offline companion."""

import argparse
import io
import pathlib
import subprocess
import tarfile


VERSION = "1.4-3+olsro2"
BASE_VERSION = "1.4-2"
PACKAGE = "vn.gsm.localiapstore"
ORIGINAL_FILES = {
    "Library/PreferenceLoader/Preferences/LocalIAPStore.plist",
    "Library/PreferenceLoader/Preferences/LocalIAPStoreIcon.png",
    "Library/PreferenceLoader/Preferences/LocalIAPStoreIcon@2x.png",
    "Library/MobileSubstrate/DynamicLibraries/LocalIAPStore.plist",
    "Library/MobileSubstrate/DynamicLibraries/LocalIAPStore.dylib",
}


def ar_member(archive: pathlib.Path, name: str) -> bytes:
    return subprocess.run(
        ["ar", "-p", str(archive), name], check=True, capture_output=True
    ).stdout


def tar_files(data: bytes) -> dict[str, tuple[bytes, int]]:
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for item in archive:
            name = item.name.removeprefix("./")
            if item.isdir():
                continue
            if not item.isfile() or name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"Unexpected archive member: {item.name}")
            result[name] = (archive.extractfile(item).read(), item.mode)
    return result


def make_tar(files: dict[str, tuple[bytes, int]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        directories = {
            str(parent)
            for name in files
            for parent in pathlib.PurePosixPath(name).parents
            if str(parent) != "."
        }
        for directory in sorted(directories, key=lambda value: (value.count("/"), value)):
            info = tarfile.TarInfo("./" + directory + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = info.gid = 0
            info.uname = "root"
            info.gname = "wheel"
            archive.addfile(info)
        for name, (content, mode) in sorted(files.items()):
            info = tarfile.TarInfo("./" + name)
            info.size = len(content)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = "root"
            info.gname = "wheel"
            archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def make_ar(members: list[tuple[str, bytes]]) -> bytes:
    result = bytearray(b"!<arch>\n")
    for name, content in members:
        if len(name) > 15:
            raise ValueError(f"ar member name too long: {name}")
        header = (
            f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}`\n"
        ).encode("ascii")
        if len(header) != 60:
            raise ValueError("Malformed ar header")
        result.extend(header)
        result.extend(content)
        if len(content) % 2:
            result.extend(b"\n")
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_deb", type=pathlib.Path)
    parser.add_argument("companion_dylib", type=pathlib.Path)
    parser.add_argument("output_deb", type=pathlib.Path)
    args = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parent

    control_files = tar_files(ar_member(args.base_deb, "control.tar.gz"))
    original_control = control_files["control"][0].decode("utf-8")
    if f"Package: {PACKAGE}\n" not in original_control:
        raise ValueError("Unexpected package identifier")
    if f"Version: {BASE_VERSION}\n" not in original_control:
        raise ValueError("Unexpected base version")
    control = original_control.replace(
        f"Version: {BASE_VERSION}\n", f"Version: {VERSION}\n", 1
    ).replace(
        "Name: LocalIAPStore\n", "Name: LocalIAPStore (olsro)\n", 1
    )
    control += "\n" if not control.endswith("\n") else ""
    control += (
        "X-Original-Version: 1.4-2\n"
        "X-Olsro-Feature: Automatic offline StoreKit product metadata for user apps\n"
    )
    control_tar = make_tar({"control": (control.encode("utf-8"), 0o644)})

    original_data = tar_files(ar_member(args.base_deb, "data.tar.gz"))
    if set(original_data) != ORIGINAL_FILES:
        raise ValueError(f"Unexpected original payload: {set(original_data) ^ ORIGINAL_FILES}")
    data = dict(original_data)
    data["Library/MobileSubstrate/DynamicLibraries/LocalAPStoreOffline.dylib"] = (
        args.companion_dylib.read_bytes(), 0o755
    )
    data["Library/MobileSubstrate/DynamicLibraries/LocalAPStoreOffline.plist"] = (
        (source / "LocalAPStoreOffline.plist").read_bytes(), 0o644
    )
    data["Library/Preferences/LocalAPStoreOfflineCatalog.plist"] = (
        (source / "LocalAPStoreOfflineCatalog.plist").read_bytes(), 0o644
    )
    deb = make_ar([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", control_tar),
        ("data.tar.gz", make_tar(data)),
    ])
    args.output_deb.parent.mkdir(parents=True, exist_ok=True)
    args.output_deb.write_bytes(deb)
    print(args.output_deb)


if __name__ == "__main__":
    main()
