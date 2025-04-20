#include "../../Global.h"

FORCEINLINE bool CheckRange(const ULONG64 input, const ULONG64 rangeStart, const ULONG64 rangeEnd)
{
	if (input >= rangeStart && input <= rangeEnd)
		return true;

	return false;
}

void SVM::HandleCPUID(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
	const UINT32 leaf = static_cast<UINT32>(guestContext->VpRegs->Rax);  // CPUID leaf value
	const UINT32 subleaf = static_cast<UINT32>(guestContext->VpRegs->Rbx); // CPUID subleaf value

	UINT32 eax = 0, ebx = 0, ecx = 0, edx = 0;

	// Execute CPUID instruction
	__cpuidex((int*)&eax, leaf, subleaf);

	// Mask out the hypervisor bit (bit 31 in EAX)
	if (leaf == 0x1) // Standard CPUID info query
	{
		eax &= ~(1 << 31); // Mask the hypervisor bit
	}

	// Store the result back in the guest registers
	guestContext->VpRegs->Rax = eax;
	guestContext->VpRegs->Rbx = ebx;
	guestContext->VpRegs->Rcx = ecx;
	guestContext->VpRegs->Rdx = edx;

	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}

void HandleMovToGpRegister(
	const UINT8* instrBytes,  // Pointer to instruction bytes (e.g., {0x48, 0x0F, 0x20, 0xE0})
	ULONG64 value,            // Value to write to the destination register
	SVM::PGUEST_CONTEXT guestContext // Guest context with registers
) {
	UINT8 rex = 0;
	size_t offset = 0;

	// Check for REX prefix (0x40-0x4F) and handle the offset if present
	if ((instrBytes[0] & 0xF0) == 0x40) {
		rex = instrBytes[0];
		offset++;
	}

	// Verify opcode for MOV from CR4: 0x0F 0x20
	if (instrBytes[offset] != 0x0F || instrBytes[offset + 1] != 0x20) {
		return; // Not a MOV from CR4 instruction
	}
	offset += 2;

	// Extract ModR/M byte (e.g., 0xE0)
	UINT8 modrm = instrBytes[offset];
	UINT8 mod = (modrm >> 6) & 0x3;  // Mod field (must be 0b11 for register-to-register)
	UINT8 reg = (modrm >> 3) & 0x7;  // Reg field (must be 0b100 for CR4)
	UINT8 rm = modrm & 0x7;          // R/M field (destination register)

	// Validate Mod and Reg fields
	if (mod != 0x3 || reg != 0x4) {
		return; // Invalid Mod or Reg field (not CR4 or register addressing)
	}

	// Calculate destination register index (accounting for REX.B)
	UINT8 rexB = (rex & 1);          // REX.B modifies the R/M field
	UINT8 regIndex = rm | (rexB << 3);

	// Use the regIndex to access and update the appropriate register in guestContext->VpRegs
	switch (regIndex) {
	case 0:  guestContext->VpRegs->Rax = value; break;
	case 1:  guestContext->VpRegs->Rcx = value; break;
	case 2:  guestContext->VpRegs->Rdx = value; break;
	case 3:  guestContext->VpRegs->Rbx = value; break;
	case 4:  guestContext->VpRegs->Rsp = value; break;
	case 5:  guestContext->VpRegs->Rbp = value; break;
	case 6:  guestContext->VpRegs->Rsi = value; break;
	case 7:  guestContext->VpRegs->Rdi = value; break;
	case 8:  guestContext->VpRegs->R8 = value; break;
	case 9:  guestContext->VpRegs->R9 = value; break;
	case 10: guestContext->VpRegs->R10 = value; break;
	case 11: guestContext->VpRegs->R11 = value; break;
	case 12: guestContext->VpRegs->R12 = value; break;
	case 13: guestContext->VpRegs->R13 = value; break;
	case 14: guestContext->VpRegs->R14 = value; break;
	case 15: guestContext->VpRegs->R15 = value; break;
	default: break; // Invalid register
	}
}

void SVM::HandleCr4Write(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext) {
	const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
	ULONG64 guestRip = vpData->GuestVmcb.StateSaveArea.Rip;

	// Read the instruction bytes (assuming 4 bytes for REX + 0x0F 0x22 + ModR/M)
	UINT8 instrBytes[4];
	Memory::ReadPhysicalAddress(
		processorIndex,
		Memory::ResolveProcessPhysicalAddress(processorIndex, vpData->GuestVmcb.StateSaveArea.Cr3, guestRip),
		instrBytes,
		sizeof(instrBytes)
	);

	size_t offset = 0;
	UINT8 rex = 0;

	// Check for REX prefix
	if ((instrBytes[0] & 0xF0) == 0x40) {
		rex = instrBytes[0];
		offset++;
	}

	// Verify opcode for MOV to CR4: 0x0F 0x22
	if (instrBytes[offset] != 0x0F || instrBytes[offset + 1] != 0x22) {
		return; // Not a MOV to CR4 instruction
	}
	offset += 2;

	// Extract ModR/M byte
	UINT8 modrm = instrBytes[offset];
	UINT8 mod = (modrm >> 6) & 0x3;
	UINT8 reg = (modrm >> 3) & 0x7; // Reg field should be 0b100 (CR4)
	UINT8 rm = modrm & 0x7;

	// Validate Mod and Reg fields
	if (mod != 0x3 || reg != 0x4) {
		return; // Invalid ModR/M for MOV to CR4
	}

	// Determine source register index (R/M field + REX.B)
	UINT8 rexB = (rex & 0x1); // REX.B extends the R/M field
	UINT8 srcRegIndex = rm | (rexB << 3);

	// Get the value from the source register in guest context
	ULONG64 guestValue = 0;
	switch (srcRegIndex) {
	case 0:  guestValue = guestContext->VpRegs->Rax; break;
	case 1:  guestValue = guestContext->VpRegs->Rcx; break;
	case 2:  guestValue = guestContext->VpRegs->Rdx; break;
	case 3:  guestValue = guestContext->VpRegs->Rbx; break;
	case 4:  guestValue = guestContext->VpRegs->Rsp; break;
	case 5:  guestValue = guestContext->VpRegs->Rbp; break;
	case 6:  guestValue = guestContext->VpRegs->Rsi; break;
	case 7:  guestValue = guestContext->VpRegs->Rdi; break;
	case 8:  guestValue = guestContext->VpRegs->R8;  break;
	case 9:  guestValue = guestContext->VpRegs->R9;  break;
	case 10: guestValue = guestContext->VpRegs->R10; break;
	case 11: guestValue = guestContext->VpRegs->R11; break;
	case 12: guestValue = guestContext->VpRegs->R12; break;
	case 13: guestValue = guestContext->VpRegs->R13; break;
	case 14: guestValue = guestContext->VpRegs->R14; break;
	case 15: guestValue = guestContext->VpRegs->R15; break;
	default: return; // Invalid register
	}

	// Preserve the host's MPK bit (bit 22) and combine with guest's value
	//const ULONG64 hostCr4 = __readcr4();
	//const ULONG64 combinedValue = (guestValue & ~(1ULL << 22)) | (hostCr4 & (1ULL << 22));

	// Write the modified value to the physical CR4
	const ULONG64 value = guestValue |= (1 << 22);
	__writecr4(value);

	// Advance guest RIP to skip the instruction
	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}

void SVM::HandleCr4Read(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext) {

	const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);

	ULONG64 guestRip = vpData->GuestVmcb.StateSaveArea.Rip;

	UINT8 buffer[3];

	Memory::ReadPhysicalAddress(processorIndex, Memory::ResolveProcessPhysicalAddress(processorIndex, vpData->GuestVmcb.StateSaveArea.Cr3, guestRip), &buffer, sizeof(buffer));

	auto cr4 = __readcr4();
	cr4 &= (1 << 22);

	HandleMovToGpRegister(buffer, cr4, guestContext);

	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;

}

void SVM::HandleMSRAccess(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
	const UINT32 msr = guestContext->VpRegs->Rcx & MAXUINT32;
	const BOOLEAN writeAccess = (vpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

#if !NESTED_MODE
	if (!Utils::CheckMSR(msr))
	{
		InjectGeneralProtectionException(vpData);
		return;
	}
#endif

	ULARGE_INTEGER value;
	if (msr == IA32_MSR_EFER)
	{
		if (writeAccess)
		{
			value.LowPart = guestContext->VpRegs->Rax & MAXUINT32;
			value.HighPart = guestContext->VpRegs->Rdx & MAXUINT32;
			value.QuadPart |= EFER_SVME;

			vpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
		}
		else
		{
			value.QuadPart = __readmsr(msr);
			value.QuadPart &= ~EFER_SVME;
			guestContext->VpRegs->Rax = value.LowPart;
			guestContext->VpRegs->Rdx = value.HighPart;
		}
	}
	else
	{
		if (writeAccess)
		{
			value.LowPart = guestContext->VpRegs->Rax & MAXUINT32;
			value.HighPart = guestContext->VpRegs->Rdx & MAXUINT32;
			__writemsr(msr, value.QuadPart);
		}
		else
		{
			value.QuadPart = __readmsr(msr);
			guestContext->VpRegs->Rax = value.LowPart;
			guestContext->VpRegs->Rdx = value.HighPart;
		}
	}

	vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}