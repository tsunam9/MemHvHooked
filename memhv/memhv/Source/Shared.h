#pragma once

namespace Shared
{
    constexpr ULONG64 MAGIC = 0xfeed3;
    constexpr ULONG64 COMM_CHECK = 0xdead;

    constexpr ULONG64 MAX_RW_SIZE = 0x10000;

    enum CommandId
    {
        Invalid,
        CheckPresence,
        GetProcess,
        GetDirectoryBase,
        CopyProcessMemory,
        ProtectSelf,
        GetProcessBaseAddress,
        CreateHook,
    };

    enum ErrorCodes
    {
        Success,
        ControlBlockReadFail,
        MemoryCopyTooLarge,
        MemoryCopyFailSource,
        MemoryCopyFailTarget,
        HookFailedToFetchPTE,
    };

    typedef struct _COPY_MEMORY_DATA
    {
        ULONG64 SourceDirectoryBase;
        ULONG64 SourceAddress;
        ULONG64 DestinationDirectoryBase;
        ULONG64 DestinationAddress;
        SIZE_T NumberOfBytes;
    } COPY_MEMORY_DATA;

    typedef struct _HOOK_DATA
    {
        ULONG64 TargetFunctionDirectoryBase;
        ULONG64 FunctionToHook;
        ULONG64 HandlerFunctionDirectoryBase;
        ULONG64 HandlerFunction;
    } HOOK_DATA;

}