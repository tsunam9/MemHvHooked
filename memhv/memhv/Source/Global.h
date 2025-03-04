#pragma once

#define NESTED_MODE true

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <minwindef.h>
#include <stddef.h>
#include <ntimage.h>

#include "Utils.h"
#include "Shared.h"

#include "Memory/Physical.h"

#include "SVM/Defines/SVM_Platform.h"
#include "SVM/Defines/SVM_NestedPaging.h"
#include "SVM/Defines/SVM_ControlArea.h"
#include "SVM/Defines/SVM_ProcessorData.h"
#include "SVM/SVM.h"
#include "SVM/Handlers/SVM_VMExit.h"

struct Hook {
    ULONG64 hookedFunction;
    ULONG64 hookedFunctionDirectoryBase;
    ULONG64 handlerFunction;
    ULONG64 handlerDirectoryBase;
    ULONG64 OldPagePhysical;
    ULONG64 NewPagePhysical;
    ULONG64 pagePTR;
    UINT8 oldkey;
};


namespace Global
{

    inline Hook G_Hooks[32];
    inline int hooksplaced;
    inline bool singlestepping;
    inline ULONG64 singlestepaddress;

    inline PVOID BlankPage = nullptr;
    inline PVOID PreallocatedPools[32];

    namespace Offsets
    {
        inline ULONG64 ActiveProcessLinks = 0x448;
    }
}