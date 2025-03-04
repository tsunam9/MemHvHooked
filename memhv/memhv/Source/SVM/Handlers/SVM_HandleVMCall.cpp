#include "../../Global.h"

__forceinline void HandleInvalid(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	guestContext->VpRegs->Rax = 0xFFFF;
}

__forceinline void HandleCheckPresence(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	guestContext->VpRegs->Rax = Shared::COMM_CHECK;
}

void HandleGetProcess(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	const ULONG64 processId = guestContext->VpRegs->R8;
	guestContext->VpRegs->Rax = reinterpret_cast<ULONG64>(Utils::FindProcess(reinterpret_cast<HANDLE>(processId)));
}

void HandleGetDirectoryBase(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	const ULONG64 targetProcess = guestContext->VpRegs->R8;

	/*
	 * If we don't reference the process object, the address space will
	 * be trashed when the process starts exiting or crashes, which will
	 * lead to system crash or freeze due to us overwriting the cr3 value
	 * when reading the memory.
	 */
	Utils::ReferenceObject(reinterpret_cast<PEPROCESS>(targetProcess));

	guestContext->VpRegs->Rax = Memory::GetDirectoryBase(reinterpret_cast<PEPROCESS>(targetProcess));
}

void HandleCopyProcessMemory(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
	const ULONG64 controlData = guestContext->VpRegs->R8;
	const ULONG64 currentProcessCr3 = guestContext->VpRegs->R9;

	Shared::COPY_MEMORY_DATA copyData = { 0 };
	SIZE_T bytesRead;
	NTSTATUS status = Memory::ReadProcessMemory(processorIndex, currentProcessCr3, controlData, &copyData, sizeof(Shared::COPY_MEMORY_DATA), &bytesRead);
	if (!NT_SUCCESS(status))
	{
		guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
		return;
	}

	if (copyData.NumberOfBytes > Shared::MAX_RW_SIZE)
	{
		guestContext->VpRegs->Rax = Shared::ErrorCodes::MemoryCopyTooLarge;
		return;
	}

	status = Memory::CopyProcessMemory(processorIndex, copyData.SourceDirectoryBase, copyData.SourceAddress, copyData.DestinationDirectoryBase, copyData.DestinationAddress, copyData.NumberOfBytes);
	if (!NT_SUCCESS(status))
	{
		guestContext->VpRegs->Rax = status == STATUS_ABANDONED ? Shared::ErrorCodes::MemoryCopyFailSource : Shared::ErrorCodes::MemoryCopyFailTarget;
		return;
	}

	guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectSelf(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	SVM::ProtectSelf(vpData->HostStackLayout.SharedVpData);

	vpData->GuestVmcb.ControlArea.VmcbClean &= 0xFFFFFFEF;
	vpData->GuestVmcb.ControlArea.TlbControl = 1;

	guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleGetBaseAddress(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
	UNREFERENCED_PARAMETER(vpData);

	PEPROCESS eProcess = (PEPROCESS)(guestContext->VpRegs->R8);
	ULONG64 target_cr3 = guestContext->VpRegs->R9;

	guestContext->VpRegs->Rax = Memory::GetProcessBaseAddress(eProcess, target_cr3);

}

void HandleCreateHook(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext) {

	if (Global::hooksplaced >= 31) {
		return;
	}

	const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
	const ULONG64 hookData = guestContext->VpRegs->R8;
	const ULONG64 currentProcessCr3 = guestContext->VpRegs->R9;
	Shared::HOOK_DATA copyData = { 0 };
	SIZE_T bytesRead;

	NTSTATUS status = Memory::ReadProcessMemory(processorIndex, currentProcessCr3, hookData, &copyData,
		sizeof(Shared::HOOK_DATA), &bytesRead);
	if (!NT_SUCCESS(status)) {
		guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
		return;
	}

	// Save original CR3
	const ULONG64 originalCr3 = __readcr3();
	// Switch to target process context
	__writecr3(copyData.TargetFunctionDirectoryBase);
	// Get the PTE for the function we want to hook
	Memory::PTE* virtual_pte = Memory::GetPte(copyData.FunctionToHook);
	ULONG64 PhysicalPTE = Memory::VirtualToPhysical((ULONG64)virtual_pte);
	__writecr3(originalCr3); // Restore CR3 before returning

	Memory::PTE pte{};
	Memory::ReadPhysicalAddress(processorIndex, PhysicalPTE, &pte, sizeof(pte));

	if (!pte.Present || pte.Xd || !pte.PageFrame) {
		guestContext->VpRegs->Rax = Shared::ErrorCodes::HookFailedToFetchPTE;
		return;
	}

	// Allocate a new page
	PVOID newPage = Utils::AllocatePageAligned(4096);
	if (!newPage) {
		guestContext->VpRegs->Rax = Shared::ErrorCodes::HookFailedToFetchPTE;
		return;
	}

	ULONG64 targetAddress = PFN_TO_PAGE(pte.PageFrame);

	Memory::ReadPhysicalAddress(processorIndex, targetAddress, newPage, 4096); // read 4kb from old page into new page

	ULONG64 offsetInPage = PFN_TO_PAGE(pte.PageFrame) & 0xFFF;

	// Create a trampoline by injecting a breakpoint at the function's entry point in our copied page
	BYTE* newPageBytes = (BYTE*)newPage;
	newPageBytes[offsetInPage] = 0xCC; // int3 instruction

	// Get physical address of our new page
	ULONG64 newPagePhysical = Memory::VirtualToPhysical((ULONG64)newPage);
	// Set the protection key to 15 as in the original code

	//BYTE int3 = 0xCC;

	//Memory::WritePhysicalAddress(processorIndex, Memory::ResolveProcessPhysicalAddress(processorIndex, copyData.TargetFunctionDirectoryBase, copyData.FunctionToHook), &int3, sizeof(int3));

	// Store hook information
	Hook temphook{};
	temphook.handlerFunction = copyData.HandlerFunction;
	temphook.handlerDirectoryBase = copyData.HandlerFunctionDirectoryBase;
	temphook.hookedFunction = copyData.FunctionToHook;
	temphook.hookedFunctionDirectoryBase = copyData.TargetFunctionDirectoryBase;
	temphook.pagePTR = PhysicalPTE;
	temphook.NewPagePhysical = newPagePhysical;
	temphook.OldPagePhysical = PFN_TO_PAGE(pte.PageFrame);
	temphook.oldkey = 0;

	pte.PageFrame = PAGE_TO_PFN(newPagePhysical);
	pte.ProtectionKey = 15;

	Memory::WritePhysicalAddress(processorIndex, PhysicalPTE, &pte, sizeof(pte));

	Global::G_Hooks[Global::hooksplaced] = temphook;
	Global::hooksplaced++;

	// Return success
	guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
	return;
}

void SVM::HandleDebugException(PVIRTUAL_PROCESSOR_DATA vpData, PGUEST_CONTEXT guestContext) {
	UNREFERENCED_PARAMETER(guestContext);

	if (vpData->GuestVmcb.StateSaveArea.Dr6 & (1 << 14)) {
		for (size_t i = 0; i < Global::hooksplaced; i++)
		{
			const UINT32 processorindex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
			Memory::PTE pte{};
			Memory::ReadPhysicalAddress(processorindex, Global::G_Hooks[i].pagePTR, &pte, sizeof(pte));
			pte.PageFrame = PAGE_TO_PFN(Global::G_Hooks[i].NewPagePhysical);
			pte.ProtectionKey = 15;
			Memory::WritePhysicalAddress(processorindex, Global::G_Hooks[i].pagePTR, &pte, sizeof(pte));
			__invlpg((void*)Global::G_Hooks[0].pagePTR);
		}
		Global::singlestepping = false;
		vpData->GuestVmcb.StateSaveArea.Dr6 = 0xFFFF0FF0; // set reserved bits and leave everything else blank;
		return;
	}
	
	EVENTINJ event;
	event.AsUInt64 = 0;
	event.Fields.Vector = 1;    // Vector 1 for #DB (was 3 for #BP)
	event.Fields.Type = 3;      // Type 3 = Hardware exception
	event.Fields.Valid = 1;     // Mark the event as valid
	vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
	
}




void SVM::HandleBreakpoint(PVIRTUAL_PROCESSOR_DATA vpData, PGUEST_CONTEXT guestContext) {

	UNREFERENCED_PARAMETER(guestContext);

	if (Global::hooksplaced) {
		for (size_t i = 0; i < Global::hooksplaced; i++)
		{
			if (vpData->GuestVmcb.StateSaveArea.Rip == Global::G_Hooks[i].hookedFunction) {
				__writecr3(Global::G_Hooks[i].handlerDirectoryBase);
				vpData->GuestVmcb.StateSaveArea.Rip = Global::G_Hooks[i].handlerFunction;
				return;
			}
		}
	}

	EVENTINJ event;
	event.AsUInt64 = 0;
	event.Fields.Vector = 3;
	event.Fields.Type = 3;
	event.Fields.Valid = 1;
	vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;

}

void SVM::HandlePageFault(PVIRTUAL_PROCESSOR_DATA vpData, PGUEST_CONTEXT guestContext) {

	UNREFERENCED_PARAMETER(guestContext);

	if (vpData->GuestVmcb.ControlArea.ExitInfo1 & (1 << 5)) {
		if (Global::hooksplaced == 1) {
			const UINT32 processorindex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
			Memory::PTE pte{};
			Memory::ReadPhysicalAddress(processorindex, Global::G_Hooks[0].pagePTR, &pte, sizeof(pte));
			pte.PageFrame = PAGE_TO_PFN(Global::G_Hooks[0].OldPagePhysical);
			pte.ProtectionKey = Global::G_Hooks[0].oldkey;
			Memory::WritePhysicalAddress(processorindex, Global::G_Hooks[0].pagePTR, &pte, sizeof(pte));
			Global::singlestepping = true;
			vpData->GuestVmcb.StateSaveArea.Rflags |= (1 << 8);
			__invlpg((void*)Global::G_Hooks[0].pagePTR);
			return;
		}
	}

	// Create an EventInj structure to inject the page fault into the guest
	EVENTINJ event;
	event.AsUInt64 = 0;
	event.Fields.Vector = EXCEPTION_VECTOR_PAGE_FAULT;    // Page fault vector
	event.Fields.Type = INTERRUPT_TYPE_HARDWARE_EXCEPTION; // It's a hardware exception

	// Check if the error code is valid (ExitInfo1 contains error code)
	event.Fields.ErrorCodeValid = 1;   // We have a valid error code (ExitInfo1)
	event.Fields.Valid = 1;             // The event is valid

	// Set the error code from ExitInfo1
	event.Fields.ErrorCode = vpData->GuestVmcb.ControlArea.ExitInfo1;  // Page fault error code

	// Inject the page fault event into the guest
	vpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;

	// Set the CR2 register (the faulting linear address)
	vpData->GuestVmcb.StateSaveArea.Cr2 = vpData->GuestVmcb.ControlArea.ExitInfo2;  // Faulting linear address
}

void SVM::HandleVMCall(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
	const ULONG64 magic = guestContext->VpRegs->Rcx;
	if (magic == Shared::MAGIC)
	{
		const ULONG64 command = guestContext->VpRegs->Rdx;
		switch (command)
		{
		case Shared::CheckPresence:
			HandleCheckPresence(vpData, guestContext);
			break;
		case Shared::GetProcess:
			HandleGetProcess(vpData, guestContext);
			break;
		case Shared::GetDirectoryBase:
			HandleGetDirectoryBase(vpData, guestContext);
			break;
		case Shared::CopyProcessMemory:
			HandleCopyProcessMemory(vpData, guestContext);
			break;
		case Shared::ProtectSelf:
			HandleProtectSelf(vpData, guestContext);
			break;
		case Shared::GetProcessBaseAddress:
			HandleGetBaseAddress(vpData, guestContext);
			break;
		case Shared::CreateHook:
			HandleCreateHook(vpData, guestContext);
			break;
		default:
			HandleInvalid(vpData, guestContext);
			break;
		}
	}
	else
	{
		InjectGeneralProtectionException(vpData);
		return;
	}

	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}