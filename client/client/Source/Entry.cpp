#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <chrono>
#include <mutex>

#include "../Library/memhv.h"

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

EXTERN_C NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE processHandle, void* baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass, void* memoryInformation, size_t memoryInformationLength, size_t* returnLength);


UINT32 LookupProcessId(const wchar_t* processName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to create snapshot. Error: " << GetLastError() << std::endl;
		return 0;
	}

	std::cout << "RUNNING CHECK ON SNAPSHOT\n";
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (Process32First(snapshot, &entry))
	{
		do
		{
			std::wcout << L"Checking process: " << entry.szExeFile << std::endl;
			if (0 == _wcsicmp(entry.szExeFile, processName))
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		} while (Process32Next(snapshot, &entry));
	}
	else
	{
		std::cout << "Failed to get first process entry. Error: " << GetLastError() << std::endl;
	}

	CloseHandle(snapshot);
	return 0;
}


std::mutex m;
ULONG64 MainModule = 0;
void ThreadBench(int id)
{
	while (true)
	{
		UINT64 totalOk = 0;
		UINT64 totalFail = 0;

		auto t1 = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 100000; i++)
		{
			int offset = rand() % 20 + 1;
			offset += 0x48;
			volatile int readValue = HV::Read<int>(MainModule + offset);
			volatile int readConfirm = HV::Read<int>(MainModule + offset);
			if (readValue == readConfirm && readValue != 0)
				totalOk++;
			else
			{
				totalFail++;
				m.lock();
				printf("[!] Invalid read: %x %x\n", readValue, readConfirm);
				m.unlock();
			}
		}
		auto t2 = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
		m.lock();
		printf("[+] Ok: %llu Fail: %llu In: %llu\n", totalOk, totalFail, duration);
		m.unlock();
	}
}

int main()
{
	printf("[>] Checking presence...\n");
	bool status = HV::CheckPresence();
	if (!status)
	{
		printf("[!] Hypervisor not running\n");
		getchar();
		return EXIT_FAILURE;
	}

	//auto cr4 = __readcr4();
	//cr4 &= (1 << 22);
	//__writecr4(cr4);

	/*
	printf("[>] Instructing hypervisor to protect itself...\n");
	status = HV::Protect();
	if (!status)
	{
		printf("[!] Hypervisor self-protection failed\n");
		getchar();
		return EXIT_FAILURE;
	}

	getchar();
	return 0;
	*/


	printf("[>] Searching for target process...\n");
	UINT32 targetProcessId = LookupProcessId(L"testapp.exe");
	if (!targetProcessId)
	{
		printf("[!] Process not found\n");
		getchar();
		return EXIT_FAILURE;
	}
	printf("[+] Process has PID of %u\n", targetProcessId);


	printf("[>] Attaching to process...\n");
	status = HV::AttachToProcess(targetProcessId);
	if (!status)
	{
		printf("[!] Failed to attach\n");
		getchar();
		return EXIT_FAILURE;
	}

	printf("[+] Current process: EPROCESS -> 0x%llx CR3 -> 0x%llx\n", HV::Data::CurrentEPROCESS, HV::Data::CurrentDirectoryBase);
	printf("[+] Target process: EPROCESS -> 0x%llx CR3 -> 0x%llx\n", HV::Data::TargetEPROCESS, HV::Data::TargetDirectoryBase);

	printf("[>] Getting module base address with process : %d\n", HV::Data::TargetEPROCESS);
	MainModule = HV::GetProcessBase(HV::Data::TargetEPROCESS);
	if (!MainModule)
	{
		printf("[!] Failed to get module base address\n");
		getchar();
		return EXIT_FAILURE;
	}

	printf("[+] Module is at 0x%llx\n", MainModule);

	printf("[>] Reading module header...\n");
	UINT64 header = HV::Read<UINT64>(MainModule);
	if (!header)
	{
		printf("[!] Failed to read header\n");
		getchar();
		return EXIT_FAILURE;
	}


	uintptr_t hookaddress1, hookaddress2;
	uintptr_t HandlerAddress1, HandlerAddress2;
	char confirmation1, confirmation2;

	while (true) {
		// Input for the first target and handler addresses


		std::cout << "INPUT FIRST HOOK ADDRESS (in hex): ";
		std::cin >> std::hex >> hookaddress1;  // Read the first target address in hexadecimal

		std::cout << "You entered first target address: 0x" << std::hex << hookaddress1 << std::dec << std::endl;

		std::cout << "INPUT FIRST HANDLER ADDRESS (in hex): ";
		std::cin >> std::hex >> HandlerAddress1;  // Read the first handler address in hexadecimal

		std::cout << "You entered first handler address: 0x" << std::hex << HandlerAddress1 << std::dec << std::endl;

		std::cout << "Do you want to confirm these addresses? (y/n): ";
		std::cin >> confirmation1;

		// Input for the second target and handler addresses
		std::cout << "INPUT SECOND HOOK ADDRESS (in hex): ";
		std::cin >> std::hex >> hookaddress2;  // Read the second target address in hexadecimal

		std::cout << "You entered second target address: 0x" << std::hex << hookaddress2 << std::dec << std::endl;

		std::cout << "INPUT SECOND HANDLER ADDRESS (in hex): ";
		std::cin >> std::hex >> HandlerAddress2;  // Read the second handler address in hexadecimal

		std::cout << "You entered second handler address: 0x" << std::hex << HandlerAddress2 << std::dec << std::endl;

		std::cout << "Do you want to confirm these addresses? (y/n): ";
		std::cin >> confirmation2;

		if ((confirmation1 == 'y' || confirmation1 == 'Y') && (confirmation2 == 'y' || confirmation2 == 'Y')) {
			// Place hooks on both target addresses
			bool hook1Success = HV::PlaceHook(hookaddress1, HandlerAddress1);
			bool hook2Success = HV::PlaceHook(hookaddress2, HandlerAddress2);

			if (hook1Success && hook2Success) {
				std::cout << "BOTH HOOKS PLACED SUCCESSFULLY!\n";
			}
			else if (hook1Success) {
				std::cout << "FIRST HOOK PLACED, SECOND HOOK FAILED!\n";
			}
			else if (hook2Success) {
				std::cout << "SECOND HOOK PLACED, FIRST HOOK FAILED!\n";
			}
			else {
				std::cout << "BOTH HOOKS FAILED TO PLACE!\n";
			}
			getchar();
			break;  // Exit the loop if the user confirms the addresses
		}
		else {
			std::cout << "Please re-enter the addresses.\n";
		}
	}


	/*
	printf("[+] Header data: 0x%p\n", reinterpret_cast<void*>(header));

	bool found = false;
	while (found == false) {
		static uint64_t i = 0;
		uint64_t p = HV::Read<uint64_t>(i * 8);
		if (p == 6942012) {
			found = true;
			printf("Found at %d\n", (MainModule + i * 8));
		}
		else {
			printf("Not found at %d | value found : %d\n", (i * 8), p);
			i++;
		}
		if (i * 8 > 0x000000000014FED0) {
			printf("Not found\n");
			break;
		}
	}
	*/
	getchar();
	return EXIT_SUCCESS;
}