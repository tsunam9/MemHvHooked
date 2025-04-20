#pragma once

#define NESTED_MODE false

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

struct SingleStepData {
    bool singlestepping;
    ULONG64 singlestepaddress;
    int hookindex;
};


struct Hook {
    ULONG64 hookedFunction;
    ULONG64 hookedFunctionDirectoryBase;
    ULONG64 handlerFunction;
    ULONG64 handlerDirectoryBase;
    ULONG64 OldPagePhysical;
    ULONG64 NewPagePhysical;
    Memory::PTE* pte;
    UINT8 oldkey;
    SingleStepData stepdata{};
};


namespace Global
{

    inline Hook G_Hooks[32];
    inline int hooksplaced;
    inline int CurrentHookIndex;

    inline PVOID BlankPage = nullptr;
    inline PVOID PreallocatedPools[32];

    namespace Offsets
    {
        inline ULONG64 ActiveProcessLinks = 0x448;
    }
}