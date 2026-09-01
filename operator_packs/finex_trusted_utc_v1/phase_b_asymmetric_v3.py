"""Offline, asymmetric Phase B closure contracts (G/P/C/A), version 3.

This module deliberately has no Windows task, firewall, network, or broker APIs.
Callers must observe Windows topology, pass its canonical projection here, and
perform mutations only after these validators succeed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

HASH = re.compile(r"^[0-9a-f]{64}$")
GENERATION = re.compile(r"^[0-9a-f]{32}$")
ROLES = {"finex-cas", "finex-fetcher", "putra-producer"}
ROLE_SIGNERS = {"finex-cas": "finex-phase-d-operator", "finex-fetcher": "finex-phase-d-operator", "putra-producer": "putra-phase-d-operator"}
READINESS_ROLES = {"finex-cas": "cas_responder", "finex-fetcher": "fetcher", "putra-producer": "producer"}
NAMESPACE = "ai-scalper-finex-phase-b-v3"


class ContractError(ValueError):
    pass


class WindowsAncestorChain:
    def __init__(self, path: Path, *, leaf_delete: bool = False, leaf_write_exclusive_delete: bool = False):
        if leaf_delete and leaf_write_exclusive_delete:raise ContractError("PUBLISH_ANCESTOR_MODE_INVALID")
        self.path=Path(os.path.abspath(os.fspath(path)));self.kernel32=None;self.handles=[];self.identities=[]
        if os.name!="nt":return
        import ctypes
        from ctypes import wintypes
        self.kernel32=ctypes.WinDLL("kernel32",use_last_error=True);k=self.kernel32
        k.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);k.CreateFileW.restype=wintypes.HANDLE
        class Info(ctypes.Structure):_fields_=[("attributes",wintypes.DWORD),("creation_low",wintypes.DWORD),("creation_high",wintypes.DWORD),("access_low",wintypes.DWORD),("access_high",wintypes.DWORD),("write_low",wintypes.DWORD),("write_high",wintypes.DWORD),("volume",wintypes.DWORD),("size_high",wintypes.DWORD),("size_low",wintypes.DWORD),("links",wintypes.DWORD),("index_high",wintypes.DWORD),("index_low",wintypes.DWORD)]
        self.Info=Info
        root=Path(self.path.anchor);parts=[];current=root
        for component in self.path.parts[1:]:current=current/component;parts.append(current)
        targets=[root,*parts]
        try:
            for index,target in enumerate(targets):
                leaf=index==len(targets)-1
                rename_parent=leaf_write_exclusive_delete and index==len(targets)-2
                access=((0x00010000|0x2|0x4) if leaf and leaf_write_exclusive_delete else (0x00010000 if leaf and leaf_delete else (0x1|0x4 if rename_parent else 0x1)))|0x00100000
                share=5 if leaf and leaf_write_exclusive_delete else 3
                reject_reparse_chain(target);handle=k.CreateFileW(str(target),access,share,None,3,0x02200000,None)
                if handle==ctypes.c_void_p(-1).value:
                    if ctypes.get_last_error()==5 and not (rename_parent or leaf and (leaf_delete or leaf_write_exclusive_delete)):access=0;handle=k.CreateFileW(str(target),access,share,None,3,0x02200000,None)
                if handle==ctypes.c_void_p(-1).value:
                    raise ContractError("PUBLISH_ANCESTOR_HOLD_FAILED")
                info=Info()
                if not k.GetFileInformationByHandle(handle,ctypes.byref(info)) or info.attributes&0x400:k.CloseHandle(handle);raise ContractError("PUBLISH_ANCESTOR_IDENTITY_FAILED")
                self.handles.append(handle);self.identities.append((str(target),info.volume,info.index_high,info.index_low,access))
            self.recheck()
        except BaseException:self.close();raise
    @property
    def leaf_handle(self):return self.handles[-1] if self.handles else None
    def recheck(self):
        if os.name!="nt":return
        import ctypes
        for expected,volume,high,low,unused_access in self.identities:
            reject_reparse_chain(Path(expected));handle=self.kernel32.CreateFileW(expected,0,7,None,3,0x02200000,None)
            if handle==ctypes.c_void_p(-1).value:raise ContractError("PUBLISH_ANCESTOR_RECHECK_FAILED")
            try:
                info=self.Info()
                if not self.kernel32.GetFileInformationByHandle(handle,ctypes.byref(info)) or info.attributes&0x400 or (info.volume,info.index_high,info.index_low)!=(volume,high,low):raise ContractError("PUBLISH_ANCESTOR_REPLACED")
            finally:self.kernel32.CloseHandle(handle)
    def detach(self):handles=self.handles;self.handles=[];self.identities=[];return handles
    def close(self):
        if self.kernel32 is not None:
            for handle in reversed(self.handles):self.kernel32.CloseHandle(handle)
        self.handles=[];self.identities=[]


def lexical_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def reject_reparse_chain(path: Path) -> None:
    current = Path(os.path.abspath(os.fspath(path)))
    for item in (current, *current.parents):
        if not os.path.lexists(item):
            continue
        junction = bool(getattr(os.path, "isjunction", lambda unused: False)(item))
        if item.is_symlink() or junction:
            raise ContractError("PUBLISH_REPARSE_FORBIDDEN")


def flush_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    return


def durable_replace(source: Path | str, destination: Path, source_handle: int | None = None, destination_parent_handle: int | None = None, *, replace: bool = True) -> None:
    if os.name != "nt":
        if replace:os.replace(source,destination)
        elif sys.platform.startswith("linux"):
            import ctypes
            libc=ctypes.CDLL(None,use_errno=True);renameat2=getattr(libc,"renameat2",None)
            if renameat2 is None:raise ContractError("PUBLISH_NOREPLACE_UNAVAILABLE")
            renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint);renameat2.restype=ctypes.c_int
            if renameat2(-100,os.fsencode(source),-100,os.fsencode(destination),1):
                error=ctypes.get_errno()
                if error in (17,39):raise ContractError("PUBLISH_CAS_CONFLICT")
                raise OSError(error,os.strerror(error),os.fspath(destination))
        elif sys.platform=="darwin":
            import ctypes
            libc=ctypes.CDLL(None,use_errno=True);renamex=getattr(libc,"renamex_np",None)
            if renamex is None:raise ContractError("PUBLISH_NOREPLACE_UNAVAILABLE")
            renamex.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint);renamex.restype=ctypes.c_int
            if renamex(os.fsencode(source),os.fsencode(destination),4):
                error=ctypes.get_errno()
                if error in (17,39):raise ContractError("PUBLISH_CAS_CONFLICT")
                raise OSError(error,os.strerror(error),os.fspath(destination))
        else:raise ContractError("PUBLISH_NOREPLACE_UNAVAILABLE")
        flush_directory(destination.parent)
        return
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);kernel32.CreateFileW.restype=wintypes.HANDLE
    owns_source=source_handle is None;handle=source_handle if source_handle is not None else kernel32.CreateFileW(str(source),0x00010000,7,None,3,0x00200000|0x02000000|0x80000000,None)
    if handle==ctypes.c_void_p(-1).value:raise ContractError("PUBLISH_SOURCE_HOLD_FAILED")
    ancestors=None;owns_parent=destination_parent_handle is None
    try:ancestors=WindowsAncestorChain(destination.parent) if owns_parent else None;parent_handle=ancestors.leaf_handle if owns_parent else destination_parent_handle
    except BaseException:
        if owns_source:kernel32.CloseHandle(handle)
        raise
    class RenameInfo(ctypes.Structure):
        _fields_=[("ReplaceIfExists",wintypes.BOOLEAN),("RootDirectory",wintypes.HANDLE),("FileNameLength",wintypes.DWORD),("FileName",wintypes.WCHAR*1)]
    class IoStatusBlock(ctypes.Structure):_fields_=[("status",ctypes.c_void_p),("information",ctypes.c_size_t)]
    name=destination.name;encoded=name.encode("utf-16le");offset=RenameInfo.FileName.offset;buffer=ctypes.create_string_buffer(offset+len(encoded)+2);ctypes.c_ubyte.from_buffer(buffer,0).value=1 if replace else 0;ctypes.c_void_p.from_buffer(buffer,RenameInfo.RootDirectory.offset).value=parent_handle;ctypes.c_uint32.from_buffer(buffer,RenameInfo.FileNameLength.offset).value=len(encoded);ctypes.memmove(ctypes.addressof(buffer)+offset,encoded,len(encoded));ntdll=ctypes.WinDLL("ntdll");ntdll.NtSetInformationFile.argtypes=(wintypes.HANDLE,ctypes.POINTER(IoStatusBlock),ctypes.c_void_p,wintypes.ULONG,ctypes.c_int);ntdll.NtSetInformationFile.restype=ctypes.c_long;ios=IoStatusBlock()
    try:status=ntdll.NtSetInformationFile(handle,ctypes.byref(ios),buffer,len(buffer),10);success=status>=0
    finally:
        if owns_source:kernel32.CloseHandle(handle)
        if ancestors is not None:ancestors.recheck();ancestors.close()
    if not success:
        if not replace and (status&0xffffffff) in (0xC0000035,0xC000003A,0xC0000101):raise ContractError("PUBLISH_CAS_CONFLICT")
        raise ContractError("PUBLISH_DURABLE_REPLACE_FAILED:"+hex(status&0xffffffff))


class ExactDirectoryHold:
    def __init__(self, streams=(), descriptor=None, kernel32=None, handles=()):self.streams=list(streams);self.descriptor=descriptor;self.kernel32=kernel32;self.handles=list(handles);self.closed=False
    def close(self):
        if self.closed:return
        self.closed=True
        for stream in self.streams:stream.close()
        if self.descriptor is not None:os.close(self.descriptor)
        if self.kernel32 is not None:
            for handle in self.handles:self.kernel32.CloseHandle(handle)


def _current_windows_sid() -> str:
    import ctypes
    from ctypes import wintypes
    advapi32=ctypes.WinDLL("advapi32",use_last_error=True);kernel32=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel32.GetCurrentProcess.restype=wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes=(wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE));advapi32.OpenProcessToken.restype=wintypes.BOOL
    advapi32.GetTokenInformation.argtypes=(wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD));advapi32.GetTokenInformation.restype=wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes=(ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR));advapi32.ConvertSidToStringSidW.restype=wintypes.BOOL
    kernel32.LocalFree.argtypes=(ctypes.c_void_p,);kernel32.LocalFree.restype=ctypes.c_void_p
    token=wintypes.HANDLE();needed=wintypes.DWORD()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),0x0008,ctypes.byref(token)):raise ContractError("PUBLISH_DIRECTORY_SEAL_FAILED")
    try:
        advapi32.GetTokenInformation(token,1,None,0,ctypes.byref(needed));buffer=ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token,1,buffer,needed,ctypes.byref(needed)):raise ContractError("PUBLISH_DIRECTORY_SEAL_FAILED")
        sid_text=wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(buffer).value,ctypes.byref(sid_text)):raise ContractError("PUBLISH_DIRECTORY_SEAL_FAILED")
        try:return sid_text.value
        finally:kernel32.LocalFree(sid_text)
    finally:kernel32.CloseHandle(token)


def seal_exact_directory(directory: Path) -> None:
    """Remove create/write rights before adoption; a pre-opened rename handle remains valid."""
    if os.name!="nt":
        for item in directory.iterdir():os.chmod(item,0o444)
        os.chmod(directory,0o555);return
    icacls=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/icacls.exe"
    if not icacls.is_file():raise ContractError("PUBLISH_DIRECTORY_SEAL_FAILED")
    result=_run([str(icacls),str(directory),"/inheritance:r","/grant:r","*"+_current_windows_sid()+":RX","*S-1-5-18:F","/T","/C","/Q"],timeout_reason="PUBLISH_DIRECTORY_SEAL_TIMEOUT")
    if result.returncode:raise ContractError("PUBLISH_DIRECTORY_SEAL_FAILED")


def unseal_directory_for_cleanup(directory: Path) -> None:
    if os.name!="nt":
        for item in directory.rglob("*"):
            try:os.chmod(item,0o700)
            except OSError:pass
        try:os.chmod(directory,0o700)
        except OSError:pass
        return
    icacls=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/icacls.exe"
    try:_run([str(icacls),str(directory),"/grant:r","*"+_current_windows_sid()+":F","*S-1-5-18:F","/T","/C","/Q"],timeout_reason="PUBLISH_DIRECTORY_CLEANUP_TIMEOUT")
    except (OSError,ContractError):pass


def adopt_exact_directory(stage: Path, destination: Path, expected: dict[str, bytes]) -> ExactDirectoryHold:
    """Adopt and return a hold that keeps the exact destination immutable until closed."""
    reject_reparse_chain(stage);reject_reparse_chain(destination.parent)
    names=set(expected)
    if os.name!="nt":
        descriptor=os.open(stage,os.O_RDONLY)
        streams=[]
        try:
            if set(os.listdir(stage))!=names:raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            for name,raw in expected.items():
                stream=(stage/name).open("rb");streams.append(stream)
                if stream.read()!=raw:raise ContractError("PUBLISH_DIRECTORY_BYTES_DRIFT")
            if set(os.listdir(stage))!=names:raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            seal_exact_directory(stage)
            durable_replace(stage,destination)
            if set(os.listdir(destination))!=names or any((destination/name).read_bytes()!=raw for name,raw in expected.items()):raise ContractError("PUBLISH_DIRECTORY_POST_ADOPTION_DRIFT")
            return ExactDirectoryHold(streams,descriptor)
        except BaseException:
            for stream in streams:stream.close()
            os.close(descriptor)
            raise
    else:
        import ctypes
        from ctypes import wintypes
        kernel32=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel32.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);kernel32.CreateFileW.restype=wintypes.HANDLE
        destination_ancestors=WindowsAncestorChain(destination.parent);stage_ancestors=WindowsAncestorChain(stage.parent);parent_handle=destination_ancestors.leaf_handle
        directory_handle=kernel32.CreateFileW(str(stage),0x80000000|0x00010000,1,None,3,0x00200000|0x02000000,None)
        if directory_handle==ctypes.c_void_p(-1).value:destination_ancestors.close();stage_ancestors.close();raise ContractError("PUBLISH_DIRECTORY_EXCLUSIVE_HOLD_FAILED")
        streams=[];file_handles=[]
        try:
            reject_reparse_chain(stage)
            if set(os.listdir(stage))!=names:raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            for name,raw in expected.items():
                reject_reparse_chain(stage/name);stream=(stage/name).open("rb");streams.append(stream)
                if stream.read()!=raw:raise ContractError("PUBLISH_DIRECTORY_BYTES_DRIFT")
            if set(os.listdir(stage))!=names:raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            for stream in streams:stream.close()
            streams.clear()
            seal_exact_directory(stage)
            if set(os.listdir(stage))!=names:raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            durable_replace(stage,destination,directory_handle,parent_handle)
            reject_reparse_chain(destination)
            for name in sorted(names):
                handle=kernel32.CreateFileW(str(destination/name),0x80000000,1,None,3,0x00200000|0x02000000,None)
                if handle==ctypes.c_void_p(-1).value:raise ContractError("PUBLISH_FILE_EXCLUSIVE_HOLD_FAILED")
                file_handles.append(handle)
            if set(os.listdir(destination))!=names or any((destination/name).read_bytes()!=raw for name,raw in expected.items()):raise ContractError("PUBLISH_DIRECTORY_POST_ADOPTION_DRIFT")
            destination_ancestors.recheck();return ExactDirectoryHold(kernel32=kernel32,handles=[*file_handles,directory_handle,*destination_ancestors.detach()])
        except BaseException:
            for stream in streams:stream.close()
            for handle in file_handles:kernel32.CloseHandle(handle)
            kernel32.CloseHandle(directory_handle);destination_ancestors.close()
            raise
        finally:stage_ancestors.close()


def hold_exact_directory(directory: Path, expected: dict[str, bytes]) -> ExactDirectoryHold:
    if os.name!="nt":
        descriptor=os.open(directory,os.O_RDONLY);streams=[]
        try:
            if set(os.listdir(directory))!=set(expected):raise ContractError("PUBLISH_DIRECTORY_TOPOLOGY_DRIFT")
            for name,raw in expected.items():
                stream=(directory/name).open("rb");streams.append(stream)
                if stream.read()!=raw:raise ContractError("PUBLISH_DIRECTORY_BYTES_DRIFT")
            return ExactDirectoryHold(streams,descriptor)
        except BaseException:
            for stream in streams:stream.close()
            os.close(descriptor);raise
    import ctypes
    from ctypes import wintypes
    kernel32=ctypes.WinDLL("kernel32",use_last_error=True);kernel32.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);kernel32.CreateFileW.restype=wintypes.HANDLE
    ancestors=WindowsAncestorChain(directory.parent);held=[]
    root=kernel32.CreateFileW(str(directory),0x80000000|0x00010000,1,None,3,0x00200000|0x02000000,None)
    if root==ctypes.c_void_p(-1).value:ancestors.close();raise ContractError("PUBLISH_DIRECTORY_EXCLUSIVE_HOLD_FAILED")
    try:
        reject_reparse_chain(directory)
        seal_exact_directory(directory)
        for name in sorted(expected):
            handle=kernel32.CreateFileW(str(directory/name),0x80000000,1,None,3,0x00200000|0x02000000,None)
            if handle==ctypes.c_void_p(-1).value:raise ContractError("PUBLISH_FILE_EXCLUSIVE_HOLD_FAILED")
            held.append(handle)
        if set(os.listdir(directory))!=set(expected) or any((directory/name).read_bytes()!=raw for name,raw in expected.items()):raise ContractError("PUBLISH_DIRECTORY_BYTES_DRIFT")
        ancestors.recheck();return ExactDirectoryHold(kernel32=kernel32,handles=[*held,root,*ancestors.detach()])
    except BaseException:
        for handle in held:kernel32.CloseHandle(handle)
        kernel32.CloseHandle(root);ancestors.close();raise


def durable_write_exact(data: bytes, destination: Path, *, keep_hold: bool = False, require_absent: bool = False, replace_held: HeldFileBytes | None = None) -> ExactDirectoryHold | None:
    if require_absent and replace_held is not None:raise ContractError("PUBLISH_CAS_MODE_INVALID")
    if replace_held is not None and (replace_held.closed if hasattr(replace_held,"closed") else replace_held.handle is None):raise ContractError("PUBLISH_PREDECESSOR_NOT_HELD")
    if os.name != "nt":
        fd,temp=tempfile.mkstemp(prefix=".phase-b-v3-publish-",dir=destination.parent)
        try:
            with os.fdopen(fd,"wb") as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            if require_absent and destination.exists():raise ContractError("PUBLISH_CAS_CONFLICT")
            durable_replace(temp,destination)
        except BaseException:
            try:os.unlink(temp)
            except OSError:pass
            raise
        return HeldFileBytes(destination) if keep_hold else None
    import ctypes
    from ctypes import wintypes
    kernel32=ctypes.WinDLL("kernel32",use_last_error=True);temporary=destination.parent/(".phase-b-v3-publish-"+os.urandom(16).hex());ancestors=WindowsAncestorChain(destination.parent)
    kernel32.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);kernel32.CreateFileW.restype=wintypes.HANDLE
    handle=kernel32.CreateFileW(str(temporary),0x80000000|0x40000000|0x00010000,1,None,1,0x80000000|0x00200000,None)
    if handle==ctypes.c_void_p(-1).value:ancestors.close();raise ContractError("PUBLISH_TEMP_CREATE_FAILED")
    parent_handle=ancestors.leaf_handle
    class RenameInfo(ctypes.Structure):_fields_=[("ReplaceIfExists",wintypes.BOOLEAN),("RootDirectory",wintypes.HANDLE),("FileNameLength",wintypes.DWORD),("FileName",wintypes.WCHAR*1)]
    class RenameInfoEx(ctypes.Structure):_fields_=[("Flags",wintypes.DWORD),("RootDirectory",wintypes.HANDLE),("FileNameLength",wintypes.DWORD),("FileName",wintypes.WCHAR*1)]
    class IoStatusBlock(ctypes.Structure):_fields_=[("status",ctypes.c_void_p),("information",ctypes.c_size_t)]
    retained=False
    try:
        written=wintypes.DWORD();payload=ctypes.create_string_buffer(data)
        if not kernel32.WriteFile(handle,payload,len(data),ctypes.byref(written),None) or written.value!=len(data) or not kernel32.FlushFileBuffers(handle):raise ContractError("PUBLISH_TEMP_WRITE_FAILED")
        encoded=destination.name.encode("utf-16le")
        if replace_held is not None:
            offset=RenameInfoEx.FileName.offset;buffer=ctypes.create_string_buffer(offset+len(encoded)+2);ctypes.c_uint32.from_buffer(buffer,0).value=0x1|0x2;ctypes.c_void_p.from_buffer(buffer,RenameInfoEx.RootDirectory.offset).value=parent_handle;ctypes.c_uint32.from_buffer(buffer,RenameInfoEx.FileNameLength.offset).value=len(encoded);info_class=65
        else:
            offset=RenameInfo.FileName.offset;buffer=ctypes.create_string_buffer(offset+len(encoded)+2);ctypes.c_ubyte.from_buffer(buffer,0).value=0 if require_absent else 1;ctypes.c_void_p.from_buffer(buffer,RenameInfo.RootDirectory.offset).value=parent_handle;ctypes.c_uint32.from_buffer(buffer,RenameInfo.FileNameLength.offset).value=len(encoded);info_class=10
        ctypes.memmove(ctypes.addressof(buffer)+offset,encoded,len(encoded))
        ntdll=ctypes.WinDLL("ntdll");ntdll.NtSetInformationFile.argtypes=(wintypes.HANDLE,ctypes.POINTER(IoStatusBlock),ctypes.c_void_p,wintypes.ULONG,ctypes.c_int);ntdll.NtSetInformationFile.restype=ctypes.c_long;ios=IoStatusBlock();status=ntdll.NtSetInformationFile(handle,ctypes.byref(ios),buffer,len(buffer),info_class)
        if status<0:raise ContractError("PUBLISH_CAS_CONFLICT:"+hex(status&0xffffffff))
        ancestors.recheck()
        position=ctypes.c_longlong()
        if not kernel32.SetFilePointerEx(handle,0,ctypes.byref(position),0):raise ContractError("PUBLISH_POST_ADOPTION_DRIFT")
        observed=ctypes.create_string_buffer(len(data));read=wintypes.DWORD()
        if not kernel32.ReadFile(handle,observed,len(data),ctypes.byref(read),None) or read.value!=len(data) or observed.raw[:read.value]!=data:raise ContractError("PUBLISH_POST_ADOPTION_DRIFT")
        if keep_hold:
            retained=True
            result=ExactDirectoryHold(kernel32=kernel32,handles=[handle,*ancestors.detach()]);result.raw=data;return result
        return None
    finally:
        if not retained:kernel32.CloseHandle(handle);ancestors.close()


def _pair_bundle(kind: str, generation_id: str, raw: bytes, signature: bytes) -> bytes:
    return canonical({"content_base64":base64.b64encode(raw).decode(),"content_sha256":sha(raw),"generation_id":generation_id,"kind":kind,"schema_version":"finex-phase-b-immutable-pair-bundle-v3","signature_base64":base64.b64encode(signature).decode(),"signature_sha256":sha(signature)})


def _decode_pair_bundle(bundle_raw: bytes, kind: str, generation_id: str) -> tuple[bytes,bytes]:
    value=strict_bytes(bundle_raw);_exact(value,{"content_base64","content_sha256","generation_id","kind","schema_version","signature_base64","signature_sha256"},"IMMUTABLE_PAIR_BUNDLE_INVALID")
    if value["schema_version"]!="finex-phase-b-immutable-pair-bundle-v3" or value["kind"]!=kind or value["generation_id"]!=generation_id:raise ContractError("IMMUTABLE_PAIR_BUNDLE_INVALID")
    try:raw=base64.b64decode(value["content_base64"],validate=True);signature=base64.b64decode(value["signature_base64"],validate=True)
    except (ValueError,base64.binascii.Error) as exc:raise ContractError("IMMUTABLE_PAIR_BUNDLE_INVALID") from exc
    if sha(raw)!=value["content_sha256"] or sha(signature)!=value["signature_sha256"]:raise ContractError("IMMUTABLE_PAIR_BUNDLE_INVALID")
    return raw,signature


def _hold_pair_bundle(path: Path, kind: str, generation_id: str, raw: bytes, signature: bytes, *, create: bool) -> ExactDirectoryHold | HeldFileBytes:
    expected=_pair_bundle(kind,generation_id,raw,signature)
    if path.exists():
        hold=HeldFileBytes(path)
        if hold.raw!=expected:hold.close();raise ContractError("IMMUTABLE_PAIR_BUNDLE_COLLISION")
        return hold
    if not create:raise ContractError("IMMUTABLE_PAIR_BUNDLE_REQUIRED")
    hold=durable_write_exact(expected,path,keep_hold=True,require_absent=True)
    hold.raw=expected
    return hold


def authoritative_pointer_path(base: Path, generation: dict) -> Path:
    if generation["sequence"]==1:return base
    return Path(str(base)+".successors")/(generation["predecessor_pointer_sha256"]+".json")


class PublishLock:
    def __init__(self,path:Path):self.path=path;self.stream=None;self.ancestor_handles=[]
    def _close_ancestors(self):
        if self.ancestor_handles:
            import ctypes
            kernel32=ctypes.WinDLL("kernel32",use_last_error=True)
            for handle in reversed(self.ancestor_handles):kernel32.CloseHandle(handle)
            self.ancestor_handles=[]
    def __enter__(self):
        reject_reparse_chain(self.path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        reject_reparse_chain(self.path)
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE)
            kernel32.CreateFileW.restype=wintypes.HANDLE
            existing=[self.path.parent]
            for item in existing:
                handle=kernel32.CreateFileW(str(item),0,3,None,3,0x02000000|0x00200000,None)
                if handle==ctypes.c_void_p(-1).value:
                    self._close_ancestors()
                    raise ContractError("PUBLISH_ANCESTOR_HOLD_FAILED")
                self.ancestor_handles.append(handle)
            try:reject_reparse_chain(self.path)
            except BaseException:
                self._close_ancestors();raise
        flags=os.O_RDWR|os.O_CREAT
        if hasattr(os,"O_NOFOLLOW"):flags|=os.O_NOFOLLOW
        try:self.stream=os.fdopen(os.open(self.path,flags,0o600),"r+b")
        except OSError as exc:
            self._close_ancestors();raise ContractError("PUBLISH_LOCK_INVALID") from exc
        try:
            if os.name=="nt":
                import msvcrt
                self.stream.seek(0);self.stream.write(b"\0");self.stream.flush();self.stream.seek(0);msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except (OSError,BlockingIOError) as exc:
            try:self.stream.close()
            except OSError:pass
            self._close_ancestors()
            raise ContractError("PUBLISH_CONCURRENT") from exc
        try:self.stream.seek(0);self.stream.truncate();self.stream.write((str(os.getpid())+"\n").encode());self.stream.flush();os.fsync(self.stream.fileno());return self
        except BaseException:
            try:self.stream.close()
            finally:self._close_ancestors()
            raise
    def __exit__(self,*unused):
        if self.stream is not None:
            try:
                self.stream.seek(0)
                if os.name=="nt":
                    import msvcrt
                    msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(),fcntl.LOCK_UN)
            finally:self.stream.close()
        self._close_ancestors()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_fingerprint(public_key: Path) -> str:
    return public_fingerprint_bytes(public_key.read_bytes())


def public_fingerprint_bytes(raw: bytes) -> str:
    parts=raw.decode("ascii").strip().split()
    if len(parts)<2 or parts[0]!="ssh-ed25519":raise ContractError("PUBLIC_KEY_INVALID")
    try:blob=base64.b64decode(parts[1],validate=True)
    except (ValueError,base64.binascii.Error) as exc:raise ContractError("PUBLIC_KEY_INVALID") from exc
    if len(blob)!=51 or blob[:4]!=b"\x00\x00\x00\x0b" or blob[4:15]!=b"ssh-ed25519" or blob[15:19]!=b"\x00\x00\x00\x20":raise ContractError("PUBLIC_KEY_INVALID")
    return sha(blob)


def normalized_public(public_key: Path) -> bytes:
    return normalized_public_bytes(public_key.read_bytes())


def normalized_public_bytes(raw: bytes) -> bytes:
    parts=raw.decode("ascii").strip().split()
    if len(parts)<2 or parts[0]!="ssh-ed25519":raise ContractError("PUBLIC_KEY_INVALID")
    public_fingerprint_bytes(raw)
    return (parts[0]+" "+parts[1]).encode("ascii")


class HeldFileBytes:
    def __init__(self,path: Path, *, hold_ancestors: bool = True, share_delete: bool = False):
        self.path=Path(path);self.raw=b"";self.handle=None;self.descriptor=None;self.kernel32=None;self.ancestor_hold=None;reject_reparse_chain(self.path)
        if os.name!="nt":
            self.descriptor=os.open(self.path,os.O_RDONLY);chunks=[]
            while True:
                chunk=os.read(self.descriptor,1024*1024)
                if not chunk:break
                chunks.append(chunk)
            self.raw=b"".join(chunks);return
        import ctypes
        from ctypes import wintypes
        self.ancestor_hold=WindowsAncestorChain(self.path.parent) if hold_ancestors else None;self.kernel32=ctypes.WinDLL("kernel32",use_last_error=True);k=self.kernel32
        k.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE);k.CreateFileW.restype=wintypes.HANDLE
        k.CloseHandle.argtypes=(wintypes.HANDLE,);k.CloseHandle.restype=wintypes.BOOL
        self.handle=k.CreateFileW(str(self.path),0x80000000,5 if share_delete else 1,None,3,0x00200000|0x02000000,None)
        if ctypes.c_void_p(self.handle).value==ctypes.c_void_p(-1).value:self.handle=None;self.close();raise ContractError("HELD_FILE_OPEN_FAILED")
        size=ctypes.c_longlong()
        if not k.GetFileSizeEx(self.handle,ctypes.byref(size)):self.close();raise ContractError("HELD_FILE_READ_FAILED")
        remaining=size.value;parts=[]
        while remaining:
            count=min(remaining,1024*1024);buffer=ctypes.create_string_buffer(count);read=wintypes.DWORD()
            if not k.ReadFile(self.handle,buffer,count,ctypes.byref(read),None) or read.value<=0:self.close();raise ContractError("HELD_FILE_READ_FAILED")
            parts.append(buffer.raw[:read.value]);remaining-=read.value
        self.raw=b"".join(parts);reject_reparse_chain(self.path)
        if self.ancestor_hold is not None:self.ancestor_hold.recheck()
    def close(self):
        if self.descriptor is not None:os.close(self.descriptor);self.descriptor=None
        if self.handle is not None:self.kernel32.CloseHandle(self.handle);self.handle=None
        if self.ancestor_hold is not None:self.ancestor_hold.close();self.ancestor_hold=None
    def __enter__(self):return self
    def __exit__(self,*unused):self.close()
    def __del__(self):self.close()


def strict_bytes(data: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ContractError("DUPLICATE_PROPERTY")
            value[key] = item
        return value
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("NON_CANONICAL_JSON") from exc
    if type(value) is not dict or canonical(value) != data:
        raise ContractError("NON_CANONICAL_JSON")
    return value


def _exact(value: dict, fields: set[str], reason: str) -> None:
    if type(value) is not dict or set(value) != fields:
        raise ContractError(reason)


def _sequence(generation_id: str, sequence: int, predecessor: str) -> None:
    if GENERATION.fullmatch(generation_id) is None or type(sequence) is not int or sequence < 1 or GENERATION.fullmatch(predecessor) is None:
        raise ContractError("SEQUENCE_INVALID")
    if (sequence == 1) != (predecessor == "0" * 32):
        raise ContractError("SEQUENCE_INVALID")


def validate_template(template: dict) -> None:
    _exact(template, {"action", "principal", "schema_version", "settings", "task_name", "task_path"}, "TASK_TEMPLATE_INVALID")
    if template["schema_version"] != "finex-task-definition-template-v3" or not all(type(template[k]) is str and template[k] for k in ("task_name", "task_path")):
        raise ContractError("TASK_TEMPLATE_INVALID")
    action = template["action"]
    _exact(action, {"arguments", "execute"}, "TASK_TEMPLATE_INVALID")
    _exact(action["arguments"], {"encoded_loader", "prefix"}, "TASK_TEMPLATE_INVALID")
    hole = action["arguments"]["encoded_loader"]
    _exact(hole, {"future_pointer_sha256", "kind"}, "TASK_TEMPLATE_INVALID")
    _exact(hole["future_pointer_sha256"], {"name", "type"}, "TASK_TEMPLATE_INVALID")
    if hole != {"future_pointer_sha256": {"name": "future_pointer_sha256", "type": "sha256"}, "kind": "phase-b-loader-v3"}:
        raise ContractError("TASK_TEMPLATE_HOLE_INVALID")
    if action["arguments"]["prefix"] != "-NoProfile -NonInteractive -EncodedCommand " or type(action["execute"]) is not str or not action["execute"]:
        raise ContractError("TASK_TEMPLATE_INVALID")
    if type(template["principal"]) is not dict or type(template["settings"]) is not dict:
        raise ContractError("TASK_TEMPLATE_INVALID")


def validate_immutable_config(value: dict) -> None:
    _exact(value,{"config_and_key_bindings_sha256","consumer_host_identity_sha256","expected_host_role","firewall_sha256","host_identity_sha256","joint_binding_sha256","powershell_path","powershell_sha256","readiness_authority","release_identity_manifest_sha256","release_identity_sha256","runtime_invocation","schema_version","source_host_identity_sha256"},"IMMUTABLE_CONFIG_INVALID")
    if value["schema_version"]!="finex-phase-b-immutable-config-v3" or HASH.fullmatch(str(value["config_and_key_bindings_sha256"])) is None or HASH.fullmatch(str(value["firewall_sha256"])) is None:raise ContractError("IMMUTABLE_CONFIG_INVALID")
    if value["expected_host_role"] not in {"finex","putra"} or any(HASH.fullmatch(str(value[key])) is None for key in ("consumer_host_identity_sha256","host_identity_sha256","joint_binding_sha256","powershell_sha256","release_identity_manifest_sha256","release_identity_sha256","source_host_identity_sha256")) or type(value["powershell_path"]) is not str or not Path(value["powershell_path"]).is_absolute():raise ContractError("IMMUTABLE_TRUST_BINDING_INVALID")
    expected_identity=value["consumer_host_identity_sha256"] if value["expected_host_role"]=="finex" else value["source_host_identity_sha256"]
    if value["host_identity_sha256"]!=expected_identity or value["consumer_host_identity_sha256"]==value["source_host_identity_sha256"]:raise ContractError("IMMUTABLE_PEER_BINDING_INVALID")
    readiness=value["readiness_authority"]
    _exact(readiness,{"public_key_file_sha256","public_key_fingerprint_sha256","signer_identity"},"READINESS_AUTHORITY_UNBOUND")
    if HASH.fullmatch(str(readiness["public_key_file_sha256"])) is None or HASH.fullmatch(str(readiness["public_key_fingerprint_sha256"])) is None or not readiness["signer_identity"]:raise ContractError("READINESS_AUTHORITY_UNBOUND")
    invocation=value["runtime_invocation"]
    fields={"attestation_path","attestation_signature_path","config_and_key_bindings_path","firewall_path","observer_path","observer_sha256","precommit_root","public_key_file_sha256","public_key_fingerprint_sha256","public_key_path","python_path","python_sha256","runtime_arguments","runtime_path","runtime_sha256","ssh_keygen_path","ssh_keygen_sha256","signer_identity","task_name","task_path","v3_core_path","v3_core_sha256"}
    _exact(invocation,fields,"RUNTIME_INVOCATION_INVALID")
    for key in ("observer_sha256","public_key_file_sha256","public_key_fingerprint_sha256","python_sha256","runtime_sha256","ssh_keygen_sha256","v3_core_sha256"):
        if HASH.fullmatch(str(invocation[key])) is None:raise ContractError("RUNTIME_INVOCATION_INVALID")
    path_fields={"attestation_path","attestation_signature_path","config_and_key_bindings_path","firewall_path","observer_path","precommit_root","public_key_path","python_path","runtime_path","ssh_keygen_path","v3_core_path"}
    if any(type(invocation[key]) is not str or not Path(invocation[key]).is_absolute() for key in path_fields):raise ContractError("RUNTIME_INVOCATION_INVALID")
    _exact(invocation["runtime_arguments"],{"named","positionals"},"RUNTIME_INVOCATION_INVALID")
    if type(invocation["runtime_arguments"]["named"]) is not dict or type(invocation["runtime_arguments"]["positionals"]) is not list:raise ContractError("RUNTIME_INVOCATION_INVALID")


def _run(args: list[str], *, stdin: bytes | None = None, timeout_reason: str = "SSHSIG_TIMEOUT") -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, input=stdin, capture_output=True, timeout=10, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ContractError(timeout_reason) from exc


def sign_bytes(data: bytes, private_key: Path, namespace: str, ssh_keygen: Path) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        payload = Path(directory) / "payload.json"
        payload.write_bytes(data)
        result = _run([str(ssh_keygen), "-Y", "sign", "-f", str(private_key), "-n", namespace, str(payload)])
        signature = Path(str(payload) + ".sig")
        if result.returncode or not signature.is_file():
            raise ContractError("SSHSIG_SIGN_FAILED")
        return signature.read_bytes()


def verify_bytes(data: bytes, signature: bytes, public_key: Path, identity: str, namespace: str, ssh_keygen: Path, *, public_key_raw: bytes | None = None) -> None:
    if public_key_raw is None:
        with HeldFileBytes(public_key) as held:return verify_bytes(data,signature,public_key,identity,namespace,ssh_keygen,public_key_raw=held.raw)
    public = normalized_public_bytes(public_key_raw).decode("ascii")
    with tempfile.TemporaryDirectory() as directory:
        allowed = Path(directory) / "allowed_signers"
        signature_path = Path(directory) / "payload.sig"
        allowed.write_text(identity + " " + public + "\n", encoding="ascii")
        signature_path.write_bytes(signature)
        with HeldFileBytes(allowed),HeldFileBytes(signature_path):
            result = _run([str(ssh_keygen), "-Y", "verify", "-f", str(allowed), "-I", identity, "-n", namespace, "-s", str(signature_path)], stdin=data)
        if result.returncode:
            raise ContractError("SSHSIG_INVALID")


def create_precommit(root: Path, *, future_pointer_path: Path, generation_id: str, sequence: int,
                     predecessor_generation_id: str, operator_role: str, immutable_config: dict,
                     task_template: dict, signer_identity: str, private_key: Path,
                     ssh_keygen: Path) -> dict:
    _sequence(generation_id, sequence, predecessor_generation_id)
    validate_template(task_template)
    validate_immutable_config(immutable_config)
    if lexical_path(Path(task_template["action"]["execute"]))!=lexical_path(Path(immutable_config["powershell_path"])):raise ContractError("POWERSHELL_TEMPLATE_CROSS_LINK_INVALID")
    runtime_role=immutable_config["runtime_invocation"]["runtime_arguments"]["named"].get("ReadinessRole")
    expected_host="putra" if operator_role=="putra-producer" else "finex"
    if operator_role not in ROLES or immutable_config["expected_host_role"]!=expected_host or signer_identity != ROLE_SIGNERS[operator_role] or runtime_role!=READINESS_ROLES[operator_role] or not future_pointer_path.is_absolute() or root.exists():
        raise ContractError("PRECOMMIT_PRECONDITION_INVALID")
    with tempfile.TemporaryDirectory() as directory:
        derived=Path(directory)/"authority.pub";result=_run([str(ssh_keygen),"-y","-f",str(private_key)])
        if result.returncode or not result.stdout:raise ContractError("PUBLIC_KEY_INVALID")
        derived.write_bytes(result.stdout.strip()+b"\n");authority={"public_key_fingerprint_sha256":public_fingerprint(derived),"public_key_sha256":sha(normalized_public(derived)),"signer_identity":signer_identity}
        predecessor_pointer_sha256="0"*64
        if sequence==1:
            if future_pointer_path.exists():raise ContractError("PRECOMMIT_PRECONDITION_INVALID")
        else:
            chain_holds=[]
            try:old_raw,old_payload,_,chain_holds=resolve_published_chain(future_pointer_path,sequence-1,derived,signer_identity,ssh_keygen,operator_role)
            finally:
                for chain_hold in chain_holds:chain_hold.close()
            if old_payload.get("generation_id")!=predecessor_generation_id:raise ContractError("PREDECESSOR_POINTER_INVALID")
            predecessor_pointer_sha256=sha(old_raw)
    generation = {
        "future_pointer_path": str(future_pointer_path), "generation_id": generation_id,
        "immutable_config": immutable_config, "installed_disabled_precondition": {"state": "Disabled", "trigger_count": 0},
        "operator_authority": authority, "operator_role": operator_role, "predecessor_generation_id": predecessor_generation_id,
        "predecessor_pointer_sha256": predecessor_pointer_sha256,
        "schema_version": "finex-phase-b-generation-v3", "sequence": sequence,
        "task_definition_template": task_template,
    }
    generation_raw = canonical(generation)
    generation_sig = sign_bytes(generation_raw, private_key, NAMESPACE + "-generation", ssh_keygen)
    pointer_payload = {
        "generation_id": generation_id, "generation_sha256": sha(generation_raw),
        "generation_signature_sha256": sha(generation_sig), "predecessor_generation_id": predecessor_generation_id,
        "predecessor_pointer_sha256": predecessor_pointer_sha256,
        "schema_version": "finex-phase-b-pointer-payload-v3", "sequence": sequence,
        "task_template_sha256": sha(canonical(task_template)),
    }
    pointer_payload_raw = canonical(pointer_payload)
    pointer = {"payload": pointer_payload, "schema_version": "finex-phase-b-pointer-envelope-v3",
               "signature_base64": base64.b64encode(sign_bytes(pointer_payload_raw, private_key, NAMESPACE + "-pointer", ssh_keygen)).decode()}
    pointer_raw = canonical(pointer)
    stage = root.parent / (".phase-b-v3-" + generation_id)
    if stage.exists():
        raise ContractError("PRECOMMIT_COLLISION")
    try:
        generation_dir = stage / "generations" / generation_id
        generation_dir.mkdir(parents=True)
        (generation_dir / "generation.json").write_bytes(generation_raw)
        (generation_dir / "generation.json.sig").write_bytes(generation_sig)
        (stage / "current.json").write_bytes(pointer_raw)
        manifest = {"future_pointer_path": str(future_pointer_path), "generation_id": generation_id,
                    "generation_sha256": sha(generation_raw), "operator_role": operator_role,
                    "pointer_sha256": sha(pointer_raw), "predecessor_pointer_sha256": predecessor_pointer_sha256, "schema_version": "finex-phase-b-precommit-plan-v3",
                    "sequence": sequence, "task_template_sha256": pointer_payload["task_template_sha256"]}
        (stage / "precommit.json").write_bytes(canonical(manifest))
        expected={
            "current.json":pointer_raw,
            "precommit.json":canonical(manifest),
            "generations/"+generation_id+"/generation.json":generation_raw,
            "generations/"+generation_id+"/generation.json.sig":generation_sig,
        }
        stage_chain=WindowsAncestorChain(stage,leaf_write_exclusive_delete=True);holds=[];adopted=False
        try:
            actual={str(item.relative_to(stage)).replace("\\","/") for item in stage.rglob("*") if item.is_file()}
            directories={str(item.relative_to(stage)).replace("\\","/") for item in stage.rglob("*") if item.is_dir()}
            expected_directories={"generations","generations/"+generation_id}
            if actual!=set(expected) or directories!=expected_directories:raise ContractError("PRECOMMIT_STAGE_TOPOLOGY_INVALID")
            for relative,raw in expected.items():
                held=HeldFileBytes(stage/relative,hold_ancestors=False,share_delete=True);holds.append(held)
                if held.raw!=raw:raise ContractError("PRECOMMIT_STAGE_BYTES_INVALID")
            stage_chain.recheck();seal_exact_directory(stage);stage_chain.recheck()
            actual={str(item.relative_to(stage)).replace("\\","/") for item in stage.rglob("*") if item.is_file()}
            directories={str(item.relative_to(stage)).replace("\\","/") for item in stage.rglob("*") if item.is_dir()}
            if actual!=set(expected) or directories!=expected_directories or any((stage/relative).read_bytes()!=raw for relative,raw in expected.items()):raise ContractError("PRECOMMIT_STAGE_SEAL_DRIFT")
            for held in holds:held.close()
            holds=[]
            source_handle=stage_chain.leaf_handle if os.name=="nt" else None
            parent_handle=stage_chain.handles[-2] if os.name=="nt" else None
            durable_replace(stage,root,source_handle,parent_handle,replace=False);adopted=True
            reject_reparse_chain(root)
            actual={str(item.relative_to(root)).replace("\\","/") for item in root.rglob("*") if item.is_file()}
            directories={str(item.relative_to(root)).replace("\\","/") for item in root.rglob("*") if item.is_dir()}
            if actual!=set(expected) or directories!=expected_directories or any((root/relative).read_bytes()!=raw for relative,raw in expected.items()):raise ContractError("PRECOMMIT_POST_ADOPTION_DRIFT")
        except BaseException as exc:
            if adopted:raise ContractError("PRECOMMIT_ADOPTED_INVALID") from exc
            raise
        finally:
            for held in holds:held.close()
            stage_chain.close()
    except BaseException:
        if stage.exists():
            import shutil
            unseal_directory_for_cleanup(stage)
            shutil.rmtree(stage)
        raise
    return manifest


def load_bundle(root: Path, public_key: Path, signer_identity: str, ssh_keygen: Path) -> tuple[dict, bytes, dict, bytes, dict]:
    manifest_raw = (root / "precommit.json").read_bytes(); manifest = strict_bytes(manifest_raw)
    pointer_raw = (root / "current.json").read_bytes(); pointer = strict_bytes(pointer_raw)
    _exact(manifest, {"future_pointer_path", "generation_id", "generation_sha256", "operator_role", "pointer_sha256", "predecessor_pointer_sha256", "schema_version", "sequence", "task_template_sha256"}, "MANIFEST_INVALID")
    _exact(pointer, {"payload", "schema_version", "signature_base64"}, "POINTER_INVALID")
    payload = pointer["payload"]
    _exact(payload, {"generation_id", "generation_sha256", "generation_signature_sha256", "predecessor_generation_id", "predecessor_pointer_sha256", "schema_version", "sequence", "task_template_sha256"}, "POINTER_INVALID")
    _sequence(payload["generation_id"], payload["sequence"], payload["predecessor_generation_id"])
    if manifest["schema_version"] != "finex-phase-b-precommit-plan-v3" or pointer["schema_version"] != "finex-phase-b-pointer-envelope-v3" or payload["schema_version"] != "finex-phase-b-pointer-payload-v3" or sha(pointer_raw) != manifest["pointer_sha256"]:
        raise ContractError("POINTER_INVALID")
    verify_bytes(canonical(payload), base64.b64decode(pointer["signature_base64"], validate=True), public_key, signer_identity, NAMESPACE + "-pointer", ssh_keygen)
    generation_dir = root / "generations" / payload["generation_id"]
    generation_raw = (generation_dir / "generation.json").read_bytes(); generation = strict_bytes(generation_raw)
    generation_sig = (generation_dir / "generation.json.sig").read_bytes()
    verify_bytes(generation_raw, generation_sig, public_key, signer_identity, NAMESPACE + "-generation", ssh_keygen)
    _exact(generation, {"future_pointer_path", "generation_id", "immutable_config", "installed_disabled_precondition", "operator_authority", "operator_role", "predecessor_generation_id", "predecessor_pointer_sha256", "schema_version", "sequence", "task_definition_template"}, "GENERATION_INVALID")
    validate_template(generation["task_definition_template"])
    validate_immutable_config(generation["immutable_config"])
    authority=generation.get("operator_authority")
    if authority!={"public_key_fingerprint_sha256":public_fingerprint(public_key),"public_key_sha256":sha(normalized_public(public_key)),"signer_identity":signer_identity} or generation["schema_version"] != "finex-phase-b-generation-v3" or generation["operator_role"] not in ROLES or signer_identity != ROLE_SIGNERS[generation["operator_role"]] or generation["installed_disabled_precondition"] != {"state":"Disabled","trigger_count":0} or sha(generation_raw) != payload["generation_sha256"] or sha(generation_sig) != payload["generation_signature_sha256"] or sha(canonical(generation["task_definition_template"])) != payload["task_template_sha256"] or any(manifest[k] != payload[k] for k in ("generation_id", "generation_sha256", "sequence", "task_template_sha256", "predecessor_pointer_sha256")) or generation["future_pointer_path"] != manifest["future_pointer_path"] or generation["operator_role"] != manifest["operator_role"] or generation["predecessor_generation_id"] != payload["predecessor_generation_id"] or generation["predecessor_pointer_sha256"]!=payload["predecessor_pointer_sha256"]:
        raise ContractError("GENERATION_POINTER_LINK_INVALID")
    return generation, generation_raw, pointer, pointer_raw, manifest


def resolve_published_chain(base: Path, final_sequence: int, public_key: Path, signer_identity: str, ssh_keygen: Path, expected_role: str) -> tuple[bytes,dict,dict,list]:
    if final_sequence<1:raise ContractError("POINTER_CHAIN_INVALID")
    holds=[];previous_raw=None;previous_payload=None
    try:
        for sequence in range(1,final_sequence+1):
            path=base if sequence==1 else Path(str(base)+".successors")/(sha(previous_raw)+".json")
            pointer_hold=HeldFileBytes(path);holds.append(pointer_hold);envelope=strict_bytes(pointer_hold.raw);_exact(envelope,{"payload","schema_version","signature_base64"},"POINTER_CHAIN_INVALID");payload=envelope["payload"]
            _exact(payload,{"generation_id","generation_sha256","generation_signature_sha256","predecessor_generation_id","predecessor_pointer_sha256","schema_version","sequence","task_template_sha256"},"POINTER_CHAIN_INVALID")
            if envelope["schema_version"]!="finex-phase-b-pointer-envelope-v3" or payload["schema_version"]!="finex-phase-b-pointer-payload-v3" or payload["sequence"]!=sequence:raise ContractError("POINTER_CHAIN_INVALID")
            if sequence==1:
                if payload["predecessor_generation_id"]!="0"*32 or payload["predecessor_pointer_sha256"]!="0"*64:raise ContractError("POINTER_CHAIN_INVALID")
            elif payload["predecessor_generation_id"]!=previous_payload["generation_id"] or payload["predecessor_pointer_sha256"]!=sha(previous_raw):raise ContractError("POINTER_CHAIN_SPLICE")
            verify_bytes(canonical(payload),base64.b64decode(envelope["signature_base64"],validate=True),public_key,signer_identity,NAMESPACE+"-pointer",ssh_keygen)
            generation_path=Path(str(base)+".generations")/(payload["generation_id"]+".generation-bundle-v3.json");generation_hold=HeldFileBytes(generation_path);holds.append(generation_hold);generation_raw,generation_sig=_decode_pair_bundle(generation_hold.raw,"signed-generation",payload["generation_id"]);generation=strict_bytes(generation_raw)
            verify_bytes(generation_raw,generation_sig,public_key,signer_identity,NAMESPACE+"-generation",ssh_keygen)
            if generation.get("schema_version")!="finex-phase-b-generation-v3" or generation.get("operator_role")!=expected_role or generation.get("generation_id")!=payload["generation_id"] or generation.get("sequence")!=sequence or generation.get("predecessor_generation_id")!=payload["predecessor_generation_id"] or generation.get("predecessor_pointer_sha256")!=payload["predecessor_pointer_sha256"] or lexical_path(Path(generation.get("future_pointer_path","")))!=lexical_path(base) or sha(generation_raw)!=payload["generation_sha256"] or sha(generation_sig)!=payload["generation_signature_sha256"] or sha(canonical(generation.get("task_definition_template")))!=payload["task_template_sha256"]:raise ContractError("GENERATION_CHAIN_LINK_INVALID")
            if signer_identity!=ROLE_SIGNERS.get(expected_role):raise ContractError("POINTER_CHAIN_ROLE_INVALID")
            previous_raw=pointer_hold.raw;previous_payload=payload
        return previous_raw,previous_payload,generation,holds
    except BaseException:
        for hold in holds:hold.close()
        raise


def materialize_loader(generation: dict, generation_raw: bytes, pointer_raw: bytes) -> dict:
    pointer_sha = sha(pointer_raw)
    trust={key:generation["immutable_config"][key] for key in ("consumer_host_identity_sha256","expected_host_role","host_identity_sha256","joint_binding_sha256","release_identity_sha256","source_host_identity_sha256")}
    bindings = {"future_pointer_path": generation["future_pointer_path"], "future_pointer_sha256": pointer_sha,
                "generation_id": generation["generation_id"], "generation_sha256": sha(generation_raw),
                "operator_role": generation["operator_role"], "schema_version": "finex-phase-b-loader-bindings-v3",
                "runtime_invocation":generation["immutable_config"]["runtime_invocation"],"sequence": generation["sequence"], "task_template_sha256": sha(canonical(generation["task_definition_template"])),"trust_binding":trust}
    binding_b64 = base64.b64encode(canonical(bindings)).decode()
    script = r"""$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$b=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__BINDINGS__'))|ConvertFrom-Json;if($b.schema_version-cne'finex-phase-b-loader-bindings-v3'){throw 'PHASE_B_V3_BINDING_INVALID'}
if(-not('PhaseBV3LoaderAncestorNative'-as[type])){Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class PhaseBV3LoaderAncestorNative{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern IntPtr CreateFileW(string n,uint a,uint s,IntPtr x,uint c,uint f,IntPtr t);}' }
function AH([string]$p){$full=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($p));$root=[IO.Path]::GetPathRoot($full);$targets=[Collections.Generic.List[string]]::new();$targets.Add($root);$cursor=$root;foreach($part in $full.Substring($root.Length).Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)){$cursor=Join-Path $cursor $part;$targets.Add($cursor)};$result=[Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new();try{foreach($target in $targets){$item=Get-Item -LiteralPath $target -Force -ErrorAction Stop;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'PHASE_B_V3_ANCESTOR_INVALID'};$raw=[PhaseBV3LoaderAncestorNative]::CreateFileW($target,0x00100080,3,[IntPtr]::Zero,3,0x02000000,[IntPtr]::Zero);if($raw-eq[System.IntPtr]::new(-1)){$error=[Runtime.InteropServices.Marshal]::GetLastWin32Error();if($error-eq5){$raw=[PhaseBV3LoaderAncestorNative]::CreateFileW($target,0,3,[IntPtr]::Zero,3,0x02000000,[IntPtr]::Zero)};if($raw-eq[System.IntPtr]::new(-1)){throw 'PHASE_B_V3_ANCESTOR_INVALID'}};$result.Add([Microsoft.Win32.SafeHandles.SafeFileHandle]::new($raw,$true))};return,$result.ToArray()}catch{foreach($handle in $result){$handle.Dispose()};throw}}
function H([byte[]]$x){$h=[Security.Cryptography.SHA256]::Create();try{return([BitConverter]::ToString($h.ComputeHash($x)).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function HOLD([string]$p,[string]$s){if(-not[IO.Path]::IsPathRooted($p)){throw 'PHASE_B_V3_PIN_INVALID'};$full=[IO.Path]::GetFullPath($p);$a=@(AH $full);$resolved=(Resolve-Path -LiteralPath $p).Path;if($full-cne$resolved){foreach($h in $a){$h.Dispose()};throw 'PHASE_B_V3_PIN_INVALID'};$chain=Get-Item -LiteralPath $resolved -Force;while($null-ne$chain){if($chain.Attributes-band[IO.FileAttributes]::ReparsePoint){foreach($h in $a){$h.Dispose()};throw 'PHASE_B_V3_PIN_INVALID'};$chain=if($chain-is[IO.DirectoryInfo]){$chain.Parent}else{$chain.Directory}};$x=[IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$m=[IO.MemoryStream]::new();$x.CopyTo($m);$raw=$m.ToArray();$m.Dispose();$x.Position=0;if((H $raw)-cne$s){throw 'PHASE_B_V3_PIN_INVALID'};return[pscustomobject]@{stream=$x;bytes=$raw;ancestors=$a}}catch{$x.Dispose();foreach($h in $a){$h.Dispose()};throw}}
function HOLDRAW([string]$p){if(-not[IO.Path]::IsPathRooted($p)){throw 'PHASE_B_V3_CHAIN_INVALID'};$full=[IO.Path]::GetFullPath($p);$a=@(AH $full);$resolved=(Resolve-Path -LiteralPath $p).Path;if($full-cne$resolved){foreach($h in $a){$h.Dispose()};throw 'PHASE_B_V3_CHAIN_INVALID'};$chain=Get-Item -LiteralPath $resolved -Force;while($null-ne$chain){if($chain.Attributes-band[IO.FileAttributes]::ReparsePoint){foreach($h in $a){$h.Dispose()};throw 'PHASE_B_V3_CHAIN_INVALID'};$chain=if($chain-is[IO.DirectoryInfo]){$chain.Parent}else{$chain.Directory}};$x=[IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$m=[IO.MemoryStream]::new();$x.CopyTo($m);$raw=$m.ToArray();$m.Dispose();$x.Position=0;return[pscustomobject]@{stream=$x;bytes=$raw;hash=(H $raw);ancestors=$a}}catch{$x.Dispose();foreach($h in $a){$h.Dispose()};throw}}
function HOLDCHAIN($bindings,$collection){$base=[IO.Path]::GetFullPath([string]$bindings.future_pointer_path);$path=$base;$last=[int]$bindings.sequence;if($last-lt1-or$last-gt100000){throw 'PHASE_B_V3_CHAIN_SEQUENCE_INVALID'};for($seq=1;$seq-le$last;$seq++){$pointer=HOLDRAW $path;$collection.Add($pointer);$envelope=[Text.Encoding]::UTF8.GetString($pointer.bytes)|ConvertFrom-Json -ErrorAction Stop;if([int]$envelope.payload.sequence-ne$seq){throw 'PHASE_B_V3_CHAIN_SEQUENCE_MISMATCH'};$generationId=[string]$envelope.payload.generation_id;if([string]::IsNullOrWhiteSpace($generationId)){throw 'PHASE_B_V3_CHAIN_GENERATION_ID_MISSING'};$generation=HOLDRAW (Join-Path ($base+'.generations') ($generationId+'.generation-bundle-v3.json'));$collection.Add($generation);if($seq-eq$last){if($pointer.hash-cne[string]$bindings.future_pointer_sha256){throw 'PHASE_B_V3_FINAL_POINTER_HASH_MISMATCH'};if($generationId-cne[string]$bindings.generation_id){throw 'PHASE_B_V3_FINAL_GENERATION_ID_MISMATCH'}}else{$path=Join-Path ($base+'.successors') ($pointer.hash+'.json')}}}
function SAME($held,[string]$p,[string]$s){$held.stream.Position=0;$m=[IO.MemoryStream]::new();$held.stream.CopyTo($m);$raw=$m.ToArray();$m.Dispose();$held.stream.Position=0;if((H $raw)-cne$s-or(H ([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $p).Path)))-cne$s){throw 'PHASE_B_V3_POST_IDENTITY_MISMATCH'}}
function PY($source,[string[]]$argv){$encoded=[Convert]::ToBase64String($source.bytes);$bootstrap="import base64,sys;src=base64.b64decode('$encoded');sys.argv=[sys.argv[1]]+sys.argv[2:];g={'__name__':'__main__','__file__':sys.argv[0]};exec(compile(src,sys.argv[0],'exec'),g,g)";& $i.python_path -I -B -c $bootstrap @argv;if($LASTEXITCODE-ne0){throw 'PHASE_B_V3_PINNED_PYTHON_FAILED'};SAME $python $i.python_path $i.python_sha256}
$i=$b.runtime_invocation;$holds=[Collections.Generic.List[object]]::new();try{HOLDCHAIN $b $holds;$python=HOLD $i.python_path $i.python_sha256;$holds.Add($python);$core=HOLD $i.v3_core_path $i.v3_core_sha256;$holds.Add($core);$runtime=HOLD $i.runtime_path $i.runtime_sha256;$holds.Add($runtime);$observer=HOLD $i.observer_path $i.observer_sha256;$holds.Add($observer);$ssh=HOLD $i.ssh_keygen_path $i.ssh_keygen_sha256;$holds.Add($ssh);$public=HOLD $i.public_key_path $i.public_key_file_sha256;$holds.Add($public);. ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($observer.bytes)))
$fw=Get-Content -Raw -LiteralPath $i.firewall_path|ConvertFrom-Json;$keys=Get-Content -Raw -LiteralPath $i.config_and_key_bindings_path|ConvertFrom-Json;$live=Get-PhaseBV3WindowsTopology $i.task_name $i.task_path $fw $keys;if($live.state-cne'Running'){throw 'PHASE_B_V3_RUNTIME_NOT_RUNNING'}
$temp=[IO.Path]::GetTempFileName();try{Write-PhaseBV3CanonicalJson $live $temp;PY $core @($i.v3_core_path,'verify-runtime-structural','--precommit',$i.precommit_root,'--live-topology',$temp,'--public-key',$i.public_key_path,'--signer-identity',$i.signer_identity,'--ssh-keygen',$i.ssh_keygen_path,'--attestation',$i.attestation_path,'--attestation-signature',$i.attestation_signature_path);SAME $core $i.v3_core_path $i.v3_core_sha256}finally{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
$named=@{};foreach($p in $i.runtime_arguments.named.PSObject.Properties){$named[$p.Name]=$p.Value};if($named.ContainsKey('ReadinessChallengePath')){$named.ReadinessGenerationId=$b.generation_id;$named.ReadinessPointerSequence=$b.sequence;$named.ReadinessPointerSha256=$b.future_pointer_sha256;$env:AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256=H ([IO.File]::ReadAllBytes([string]$named.ReadinessChallengePath))};if([IO.Path]::GetExtension($i.runtime_path)-cne'.ps1'){throw 'PHASE_B_V3_RUNTIME_KIND_UNSUPPORTED'};& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($runtime.bytes))) @named @($i.runtime_arguments.positionals);SAME $runtime $i.runtime_path $i.runtime_sha256
}finally{foreach($held in $holds){$held.stream.Dispose();foreach($ancestor in @($held.ancestors)){$ancestor.Dispose()}}}
""".replace("__BINDINGS__",binding_b64)
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return {"decoded_bindings": bindings, "encoded_command": encoded, "encoded_command_sha256": sha(encoded.encode()), "schema_version": "finex-phase-b-materialized-loader-v3"}


def verify_materialized(root: Path, materialized_raw: bytes, public_key: Path, signer_identity: str,
                        ssh_keygen: Path, expected_role: str, expected_release_root: Path) -> dict:
    generation,generation_raw,_,pointer_raw,_=load_bundle(root,public_key,signer_identity,ssh_keygen)
    expected=materialize_loader(generation,generation_raw,pointer_raw)
    supplied=strict_bytes(materialized_raw)
    if supplied!=expected or generation["operator_role"]!=expected_role or Path(generation["future_pointer_path"]).exists():raise ContractError("MATERIALIZED_PREINSTALL_INVALID")
    invocation=expected["decoded_bindings"]["runtime_invocation"]
    release=lexical_path(expected_release_root)
    for key in ("runtime_path","observer_path","v3_core_path"):
        candidate=lexical_path(Path(invocation[key]));prefix=release+os.sep
        if candidate!=release and not candidate.startswith(prefix):raise ContractError("MATERIALIZED_RELEASE_BINDING_INVALID")
    return expected


def _write_attestation_compatibility_pair(target: Path, generation_id: str, raw: bytes, signature: bytes) -> str:
    if target.name!="attestation.json" or target.parent.name!=generation_id:raise ContractError("ATTESTATION_GENERATION_PATH_REQUIRED")
    final=target.parent;signature_target=final/"attestation.json.sig"
    if final.exists():
        reject_reparse_chain(final);reject_reparse_chain(target);reject_reparse_chain(signature_target)
        if target.is_file() and signature_target.is_file() and target.read_bytes()==raw and signature_target.read_bytes()==signature:return "already-attested"
        raise ContractError("ATTESTATION_COLLISION")
    final.parent.mkdir(parents=True,exist_ok=True);reject_reparse_chain(final.parent);reject_reparse_chain(final);stage=final.parent/(generation_id+".attestation-stage")
    if stage.exists():
        reject_reparse_chain(stage)
        if not stage.is_dir():raise ContractError("ATTESTATION_RECOVERY_CONFLICT")
        allowed={"attestation.json","attestation.json.sig"};items=list(stage.iterdir())
        if any(item.name not in allowed or item.is_symlink() or not item.is_file() for item in items):raise ContractError("ATTESTATION_RECOVERY_CONFLICT")
        complete=all((stage/name).is_file() for name in allowed)
        if complete:
            reject_reparse_chain(stage/"attestation.json");reject_reparse_chain(stage/"attestation.json.sig")
            if (stage/"attestation.json").read_bytes()!=raw or (stage/"attestation.json.sig").read_bytes()!=signature:raise ContractError("ATTESTATION_RECOVERY_CONFLICT")
        else:
            for item in items:item.unlink()
            stage.rmdir();stage.mkdir()
    else:
        stage.mkdir()
    if not (stage/"attestation.json").exists():
        (stage/"attestation.json").write_bytes(raw)
    if not (stage/"attestation.json.sig").exists():
        (stage/"attestation.json.sig").write_bytes(signature)
    for item in (stage/"attestation.json",stage/"attestation.json.sig"):
        reject_reparse_chain(item)
        for item in (stage/"attestation.json",stage/"attestation.json.sig"):
            with item.open("r+b") as stream:os.fsync(stream.fileno())
    reject_reparse_chain(stage)
    if {item.name for item in stage.iterdir()}!={"attestation.json","attestation.json.sig"}:raise ContractError("ATTESTATION_RECOVERY_CONFLICT")
    hold=adopt_exact_directory(stage,final,{"attestation.json":raw,"attestation.json.sig":signature})
    try:
        reject_reparse_chain(final);reject_reparse_chain(target);reject_reparse_chain(signature_target)
        if set(os.listdir(final))!={"attestation.json","attestation.json.sig"} or target.read_bytes()!=raw or signature_target.read_bytes()!=signature:raise ContractError("ATTESTATION_POST_ADOPTION_DRIFT")
        return "attested"
    finally:hold.close()


def write_attestation_generation(target: Path, generation_id: str, raw: bytes, signature: bytes) -> str:
    if target.name!="attestation.json" or target.parent.name!=generation_id:raise ContractError("ATTESTATION_GENERATION_PATH_REQUIRED")
    bundle_path=target.parent.parent/(generation_id+".attestation-bundle-v3.json")
    bundle_path.parent.mkdir(parents=True,exist_ok=True);reject_reparse_chain(bundle_path)
    bundle_hold=_hold_pair_bundle(bundle_path,"topology-attestation",generation_id,raw,signature,create=True)
    try:return _write_attestation_compatibility_pair(target,generation_id,raw,signature)
    finally:bundle_hold.close()


def _read_attestation_pair(target: Path, signature_target: Path) -> tuple[bytes,bytes]:
    generation_id=target.parent.name;bundle_path=target.parent.parent/(generation_id+".attestation-bundle-v3.json")
    bundle_hold=HeldFileBytes(bundle_path)
    try:
        raw,signature=_decode_pair_bundle(bundle_hold.raw,"topology-attestation",generation_id)
        with HeldFileBytes(target) as raw_hold,HeldFileBytes(signature_target) as signature_hold:
            if raw_hold.raw!=raw or signature_hold.raw!=signature:raise ContractError("ATTESTATION_COMPATIBILITY_PAIR_DRIFT")
        return raw,signature
    finally:bundle_hold.close()


def normalize_live_topology(live: dict, loader: dict, template: dict, *, include_state: bool) -> dict:
    _exact(live, {"action", "config_and_key_bindings", "definition_xml_sha256", "firewall", "principal", "settings", "state", "task_name", "task_path", "trigger_count"}, "LIVE_TOPOLOGY_INVALID")
    action = live["action"]
    _exact(action, {"arguments", "execute"}, "LIVE_TOPOLOGY_INVALID")
    expected_arguments = template["action"]["arguments"]["prefix"] + loader["encoded_command"]
    if action != {"arguments": expected_arguments, "execute": template["action"]["execute"]} or live["task_name"] != template["task_name"] or live["task_path"] != template["task_path"] or live["principal"] != template["principal"] or live["settings"] != template["settings"]:
        raise ContractError("LIVE_TEMPLATE_DRIFT")
    if HASH.fullmatch(str(live["definition_xml_sha256"])) is None or type(live["config_and_key_bindings"]) is not dict or type(live["firewall"]) is not dict:
        raise ContractError("LIVE_TOPOLOGY_INVALID")
    result = {"action": action, "config_and_key_bindings":live["config_and_key_bindings"],"definition_xml_sha256":live["definition_xml_sha256"],"firewall":live["firewall"],"principal": live["principal"], "settings": live["settings"], "task_name": live["task_name"], "task_path": live["task_path"], "trigger_count": live["trigger_count"]}
    if include_state:
        result["state"] = live["state"]
    return result


def create_attestation(generation: dict, generation_raw: bytes, pointer_raw: bytes, loader: dict, live: dict,
                       private_key: Path, ssh_keygen: Path) -> tuple[bytes, bytes]:
    topology = normalize_live_topology(live, loader, generation["task_definition_template"], include_state=True)
    if topology["state"] != "Disabled" or topology["trigger_count"] != 0:
        raise ContractError("INSTALL_PRECONDITION_INVALID")
    value = {"decoded_loader_bindings": loader["decoded_bindings"], "generation_id": generation["generation_id"],
             "generation_sequence": generation["sequence"], "generation_sha256": sha(generation_raw),
             "installed_disabled_topology": topology, "loader_command_sha256": loader["encoded_command_sha256"],
             "pointer_sha256": sha(pointer_raw), "schema_version": "finex-phase-b-topology-attestation-v3",
             "task_template_sha256": sha(canonical(generation["task_definition_template"]))}
    raw = canonical(value)
    return raw, sign_bytes(raw, private_key, NAMESPACE + "-topology", ssh_keygen)


def verify_closure(root: Path, attestation_raw: bytes, attestation_sig: bytes, live: dict, public_key: Path,
                   signer_identity: str, ssh_keygen: Path, *, require_disabled: bool) -> tuple[dict, bytes, dict]:
    generation, generation_raw, _, pointer_raw, _ = load_bundle(root, public_key, signer_identity, ssh_keygen)
    attestation = strict_bytes(attestation_raw)
    verify_bytes(attestation_raw, attestation_sig, public_key, signer_identity, NAMESPACE + "-topology", ssh_keygen)
    _exact(attestation, {"decoded_loader_bindings", "generation_id", "generation_sequence", "generation_sha256", "installed_disabled_topology", "loader_command_sha256", "pointer_sha256", "schema_version", "task_template_sha256"}, "ATTESTATION_INVALID")
    if attestation["schema_version"] != "finex-phase-b-topology-attestation-v3":
        raise ContractError("ATTESTATION_INVALID")
    loader = materialize_loader(generation, generation_raw, pointer_raw)
    topology = normalize_live_topology(live, loader, generation["task_definition_template"], include_state=require_disabled)
    if sha(canonical(live["config_and_key_bindings"]))!=generation["immutable_config"]["config_and_key_bindings_sha256"]:raise ContractError("IMMUTABLE_CONFIG_BINDING_DRIFT")
    if live["state"]=="Running" and sha(canonical(live["firewall"]))!=generation["immutable_config"]["firewall_sha256"]:raise ContractError("ACTIVE_FIREWALL_BINDING_DRIFT")
    if require_disabled and (topology["state"] != "Disabled" or topology["trigger_count"] != 0):
        raise ContractError("INSTALL_PRECONDITION_INVALID")
    expected_links = {"generation_id": generation["generation_id"], "generation_sequence": generation["sequence"],
                      "generation_sha256": sha(generation_raw), "loader_command_sha256": loader["encoded_command_sha256"],
                      "pointer_sha256": sha(pointer_raw), "task_template_sha256": sha(canonical(generation["task_definition_template"]))}
    if any(attestation.get(k) != v for k, v in expected_links.items()) or attestation.get("decoded_loader_bindings") != loader["decoded_bindings"]:
        raise ContractError("ATTESTATION_LINK_INVALID")
    attested = attestation.get("installed_disabled_topology")
    if require_disabled:
        if topology != attested:
            raise ContractError("INSTALLED_TOPOLOGY_DRIFT")
    else:
        structural_attested = {k: v for k, v in attested.items() if k not in {"state", "firewall"}}
        structural_live = {k: v for k, v in topology.items() if k != "firewall"}
        if structural_live != structural_attested:
            raise ContractError("RUNTIME_STRUCTURAL_DRIFT")
        chain_holds=[]
        try:chain_raw,_,chain_generation,chain_holds=resolve_published_chain(Path(generation["future_pointer_path"]),generation["sequence"],public_key,signer_identity,ssh_keygen,generation["operator_role"])
        except ContractError as exc:raise ContractError("CURRENT_POINTER_NOT_EXACT_PRECOMMIT") from exc
        finally:
            for chain_hold in chain_holds:chain_hold.close()
        if chain_raw!=pointer_raw or chain_generation["generation_id"]!=generation["generation_id"]:raise ContractError("CURRENT_POINTER_NOT_EXACT_PRECOMMIT")
    return generation, pointer_raw, loader


def publish_exact(root: Path, attestation_raw: bytes, attestation_sig: bytes, live: dict, destination: Path,
                  public_key: Path, signer_identity: str, ssh_keygen: Path) -> str:
    generation, pointer_raw, _ = verify_closure(root, attestation_raw, attestation_sig, live, public_key, signer_identity, ssh_keygen, require_disabled=True)
    generation_raw=canonical(generation);pointer=strict_bytes(pointer_raw);expected_signature=(root/"generations"/generation["generation_id"]/"generation.json.sig").read_bytes()
    if sha(expected_signature)!=pointer["payload"]["generation_signature_sha256"]:raise ContractError("PRECOMMIT_TOCTOU_DRIFT")
    reject_reparse_chain(destination)
    if lexical_path(destination)!=lexical_path(Path(generation["future_pointer_path"])):
        raise ContractError("FUTURE_POINTER_PATH_MISMATCH")
    pointer_destination=authoritative_pointer_path(destination,generation)
    destination.parent.mkdir(parents=True, exist_ok=True)
    reject_reparse_chain(destination)
    lock_path=Path(str(destination)+".publish.lock")
    with PublishLock(lock_path):
        old_raw=None;old_generation_hold=None;generation_hold=None;old_pointer_hold=None;pointer_hold=None;pointer_replay_hold=None;chain_pointer_holds=[]
        try:
            generation_root=Path(str(destination)+".generations");reject_reparse_chain(generation_root);generation_root.mkdir(parents=True,exist_ok=True);reject_reparse_chain(generation_root)
            adopted=generation_root/(generation["generation_id"]+".generation-bundle-v3.json")
            if pointer_destination.exists():
                pointer_replay_hold=HeldFileBytes(pointer_destination)
                if pointer_replay_hold.raw!=pointer_raw:raise ContractError("PUBLISH_CAS_CONFLICT")
                if generation["sequence"]==1:
                    replay_hold=_hold_pair_bundle(adopted,"signed-generation",generation["generation_id"],generation_raw,expected_signature,create=False)
                    try:return "already-published"
                    finally:replay_hold.close()
            if generation["sequence"]>1:
                old_raw,old,old_generation,chain_pointer_holds=resolve_published_chain(destination,generation["sequence"]-1,public_key,signer_identity,ssh_keygen,generation["operator_role"])
                if generation["sequence"]!=old.get("sequence",-1)+1 or generation["predecessor_generation_id"]!=old.get("generation_id") or generation["predecessor_pointer_sha256"]!=sha(old_raw):raise ContractError("ANTI_ROLLBACK_CONFLICT")
                if old_generation.get("generation_id")!=generation["predecessor_generation_id"] or old_generation.get("operator_role")!=generation["operator_role"]:raise ContractError("PREDECESSOR_CHAIN_INVALID")
            elif destination.exists():raise ContractError("PUBLISH_CAS_CONFLICT")
            if pointer_replay_hold is not None:
                replay_hold=_hold_pair_bundle(adopted,"signed-generation",generation["generation_id"],generation_raw,expected_signature,create=False)
                try:return "already-published"
                finally:replay_hold.close()
            generation_hold=_hold_pair_bundle(adopted,"signed-generation",generation["generation_id"],generation_raw,expected_signature,create=True)
            if old_raw is None and destination.exists():raise ContractError("PUBLISH_TOCTOU_DRIFT")
            pointer_destination.parent.mkdir(parents=True,exist_ok=True);reject_reparse_chain(pointer_destination)
            pointer_hold=durable_write_exact(pointer_raw,pointer_destination,keep_hold=True,require_absent=True)
            if pointer_hold.raw!=pointer_raw or generation_hold.raw!=_pair_bundle("signed-generation",generation["generation_id"],generation_raw,expected_signature):raise ContractError("POINTER_POST_ADOPTION_DRIFT")
            return "published"
        finally:
            if pointer_hold is not None:pointer_hold.close()
            if pointer_replay_hold is not None:pointer_replay_hold.close()
            if old_pointer_hold is not None:old_pointer_hold.close()
            for chain_hold in chain_pointer_holds:chain_hold.close()
            if generation_hold is not None:generation_hold.close()
            if old_generation_hold is not None:old_generation_hold.close()


def verify_activation_precondition(root: Path, attestation_raw: bytes, attestation_sig: bytes, live: dict,
                                   public_key: Path, signer_identity: str, ssh_keygen: Path) -> dict:
    generation, pointer_raw, loader = verify_closure(root, attestation_raw, attestation_sig, live, public_key, signer_identity, ssh_keygen, require_disabled=True)
    chain_holds=[]
    try:chain_raw,_,chain_generation,chain_holds=resolve_published_chain(Path(generation["future_pointer_path"]),generation["sequence"],public_key,signer_identity,ssh_keygen,generation["operator_role"])
    except ContractError as exc:raise ContractError("CURRENT_POINTER_NOT_EXACT_PRECOMMIT") from exc
    finally:
        for chain_hold in chain_holds:chain_hold.close()
    if chain_raw!=pointer_raw or chain_generation["generation_id"]!=generation["generation_id"]:raise ContractError("CURRENT_POINTER_NOT_EXACT_PRECOMMIT")
    return {"generation_id":generation["generation_id"],"loader_command_sha256":loader["encoded_command_sha256"],"pointer_sha256":sha(pointer_raw),"schema_version":"finex-phase-b-activation-precondition-v3"}


def verify_runtime(root: Path, attestation_raw: bytes, attestation_sig: bytes, live: dict, readiness_raw: bytes,
                   readiness_sig: bytes, readiness_public_key: Path, readiness_identity: str,
                   public_key: Path, signer_identity: str, ssh_keygen: Path) -> None:
    generation, pointer_raw, _ = verify_closure(root, attestation_raw, attestation_sig, live, public_key, signer_identity, ssh_keygen, require_disabled=False)
    if live.get("state")!="Running":raise ContractError("RUNTIME_NOT_RUNNING")
    authority=generation["immutable_config"].get("readiness_authority") if type(generation["immutable_config"]) is dict else None
    _exact(authority,{"public_key_file_sha256","public_key_fingerprint_sha256","signer_identity"},"READINESS_AUTHORITY_UNBOUND")
    readiness_hold=HeldFileBytes(readiness_public_key)
    if sha(readiness_hold.raw)!=authority["public_key_file_sha256"] or public_fingerprint_bytes(readiness_hold.raw)!=authority["public_key_fingerprint_sha256"] or readiness_identity!=authority["signer_identity"]:
        raise ContractError("READINESS_AUTHORITY_UNBOUND")
    readiness = strict_bytes(readiness_raw)
    if readiness.get("schema_version")=="finex-role-readiness-envelope-v1":
        _exact(readiness,{"payload","schema_version","signature_base64"},"READINESS_INVALID");payload=readiness["payload"];named=generation["immutable_config"]["runtime_invocation"]["runtime_arguments"]["named"]
        challenge_raw=Path(str(named.get("ReadinessChallengePath",""))).read_bytes();challenge=strict_bytes(challenge_raw);_exact(challenge,{"baseline_head_sha256","baseline_revision","deadline_utc","generation_id","issued_at_utc","nonce","pointer_sha256","role","schema_version","task_name"},"READINESS_INVALID")
        expected_role=str(named.get("ReadinessRole",""));expected_task=generation["task_definition_template"]["task_name"]
        if challenge.get("schema_version")!="finex-role-readiness-challenge-v3" or challenge.get("generation_id")!=generation["generation_id"] or challenge.get("pointer_sha256")!=sha(pointer_raw) or challenge.get("role")!=expected_role or challenge.get("task_name")!=expected_task:raise ContractError("READINESS_INVALID")
        _exact(payload,{"challenge_sha256","completed_utc","generation_id","nonce","operation","pointer_sequence","readiness_public_key_sha256","role","schema_version","success_evidence_sha256","task_name"},"READINESS_INVALID")
        if payload.get("schema_version")!="finex-role-readiness-payload-v1" or payload.get("challenge_sha256")!=sha(challenge_raw) or payload.get("generation_id")!=generation["generation_id"] or payload.get("nonce")!=challenge["nonce"] or payload.get("pointer_sequence")!=generation["sequence"] or payload.get("readiness_public_key_sha256")!=authority["public_key_fingerprint_sha256"] or payload.get("role")!=expected_role or payload.get("task_name")!=expected_task:raise ContractError("READINESS_BINDING_INVALID")
        verify_bytes(canonical(payload),base64.b64decode(readiness["signature_base64"],validate=True),readiness_public_key,readiness_identity,"ai-scalper-finex-role-readiness-v1",ssh_keygen,public_key_raw=readiness_hold.raw)
    else:
        _exact(readiness, {"generation_id", "pointer_sha256", "role", "schema_version", "state", "task_name"}, "READINESS_INVALID")
        if readiness != {"generation_id": generation["generation_id"], "pointer_sha256": sha(pointer_raw), "role": generation["operator_role"], "schema_version": "finex-phase-b-role-readiness-v3", "state": "Running", "task_name": generation["task_definition_template"]["task_name"]}:raise ContractError("READINESS_BINDING_INVALID")
        verify_bytes(readiness_raw, readiness_sig, readiness_public_key, readiness_identity, NAMESPACE + "-readiness", ssh_keygen,public_key_raw=readiness_hold.raw)
    readiness_hold.close()


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def main(argv=None) -> int:
    parser=argparse.ArgumentParser();commands=parser.add_subparsers(dest="command",required=True)
    def common(command):
        command.add_argument("--precommit",required=True);command.add_argument("--live-topology",required=True);command.add_argument("--public-key",required=True);command.add_argument("--signer-identity",required=True);command.add_argument("--ssh-keygen",required=True)
    attest=commands.add_parser("attest-installed-disabled");common(attest);attest.add_argument("--private-key",required=True);attest.add_argument("--output",required=True)
    publish=commands.add_parser("publish");common(publish);publish.add_argument("--attestation",required=True);publish.add_argument("--attestation-signature",required=True);publish.add_argument("--destination",required=True)
    publication=commands.add_parser("verify-publish");common(publication);publication.add_argument("--attestation",required=True);publication.add_argument("--attestation-signature",required=True)
    activation=commands.add_parser("verify-activation");common(activation);activation.add_argument("--attestation",required=True);activation.add_argument("--attestation-signature",required=True);activation.add_argument("--output",required=True)
    runtime=commands.add_parser("verify-runtime-structural");common(runtime);runtime.add_argument("--attestation",required=True);runtime.add_argument("--attestation-signature",required=True)
    readiness=commands.add_parser("verify-runtime-readiness");common(readiness);readiness.add_argument("--attestation",required=True);readiness.add_argument("--attestation-signature",required=True);readiness.add_argument("--readiness",required=True);readiness.add_argument("--readiness-signature");readiness.add_argument("--readiness-public-key",required=True);readiness.add_argument("--readiness-identity",required=True)
    plan=commands.add_parser("create-precommit");plan.add_argument("--root",required=True);plan.add_argument("--future-pointer",required=True);plan.add_argument("--generation-id",required=True);plan.add_argument("--sequence",required=True,type=int);plan.add_argument("--predecessor-generation-id",required=True);plan.add_argument("--operator-role",required=True,choices=sorted(ROLES));plan.add_argument("--immutable-config",required=True);plan.add_argument("--task-template",required=True);plan.add_argument("--signer-identity",required=True);plan.add_argument("--private-key",required=True);plan.add_argument("--ssh-keygen",required=True)
    materialize=commands.add_parser("materialize-loader");materialize.add_argument("--precommit",required=True);materialize.add_argument("--public-key",required=True);materialize.add_argument("--signer-identity",required=True);materialize.add_argument("--ssh-keygen",required=True);materialize.add_argument("--output",required=True)
    verify_materialized_command=commands.add_parser("verify-materialized");verify_materialized_command.add_argument("--precommit",required=True);verify_materialized_command.add_argument("--materialized",required=True);verify_materialized_command.add_argument("--public-key",required=True);verify_materialized_command.add_argument("--signer-identity",required=True);verify_materialized_command.add_argument("--ssh-keygen",required=True);verify_materialized_command.add_argument("--expected-role",required=True,choices=sorted(ROLES));verify_materialized_command.add_argument("--expected-release-root",required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=="create-precommit":
            create_precommit(Path(args.root),future_pointer_path=Path(args.future_pointer),generation_id=args.generation_id,sequence=args.sequence,predecessor_generation_id=args.predecessor_generation_id,operator_role=args.operator_role,immutable_config=strict_bytes(_read(args.immutable_config)),task_template=strict_bytes(_read(args.task_template)),signer_identity=args.signer_identity,private_key=Path(args.private_key),ssh_keygen=Path(args.ssh_keygen));return 0
        if args.command=="materialize-loader":
            root=Path(args.precommit);generation,generation_raw,_,pointer_raw,_=load_bundle(root,Path(args.public_key),args.signer_identity,Path(args.ssh_keygen));Path(args.output).write_bytes(canonical(materialize_loader(generation,generation_raw,pointer_raw)));return 0
        if args.command=="verify-materialized":
            verify_materialized(Path(args.precommit),_read(args.materialized),Path(args.public_key),args.signer_identity,Path(args.ssh_keygen),args.expected_role,Path(args.expected_release_root));return 0
        live=strict_bytes(_read(args.live_topology));root=Path(args.precommit);public=Path(args.public_key);ssh=Path(args.ssh_keygen)
        if args.command=="attest-installed-disabled":
            generation,generation_raw,_,pointer_raw,_=load_bundle(root,public,args.signer_identity,ssh);loader=materialize_loader(generation,generation_raw,pointer_raw);raw,sig=create_attestation(generation,generation_raw,pointer_raw,loader,live,Path(args.private_key),ssh);target=Path(args.output)
            write_attestation_generation(target,generation["generation_id"],raw,sig)
        elif args.command=="publish":
            attestation_raw,attestation_sig=_read_attestation_pair(Path(args.attestation),Path(args.attestation_signature));publish_exact(root,attestation_raw,attestation_sig,live,Path(args.destination),public,args.signer_identity,ssh)
        elif args.command=="verify-publish":
            attestation_raw,attestation_sig=_read_attestation_pair(Path(args.attestation),Path(args.attestation_signature));verify_closure(root,attestation_raw,attestation_sig,live,public,args.signer_identity,ssh,require_disabled=True)
        elif args.command=="verify-activation":
            attestation_raw,attestation_sig=_read_attestation_pair(Path(args.attestation),Path(args.attestation_signature));value=verify_activation_precondition(root,attestation_raw,attestation_sig,live,public,args.signer_identity,ssh);target=Path(args.output);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(canonical(value))
        elif args.command=="verify-runtime-structural":
            if live.get("state")!="Running":raise ContractError("RUNTIME_NOT_RUNNING")
            attestation_raw,attestation_sig=_read_attestation_pair(Path(args.attestation),Path(args.attestation_signature));verify_closure(root,attestation_raw,attestation_sig,live,public,args.signer_identity,ssh,require_disabled=False)
        else:
            attestation_raw,attestation_sig=_read_attestation_pair(Path(args.attestation),Path(args.attestation_signature));verify_runtime(root,attestation_raw,attestation_sig,live,_read(args.readiness),_read(args.readiness_signature) if args.readiness_signature else b"",Path(args.readiness_public_key),args.readiness_identity,public,args.signer_identity,ssh)
        return 0
    except (OSError,UnicodeError,ValueError,KeyError,TypeError,json.JSONDecodeError,subprocess.SubprocessError):
        return 2


if __name__=="__main__":
    raise SystemExit(main())
