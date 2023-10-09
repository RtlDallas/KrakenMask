#pragma once

#include "struct.h"

#include <bcrypt.h>

#define TEXT_HASH							0xb80c0d8
#define SECTION_HEADER_SIZE						40

#define HASH_TpReleaseCleanupGroupMembers               		0x3400090a
#define HASH_NtContinue							0x780a612c
#define HASH_NtTestAlert						0x7915b7df
#define HASH_NtAlertResumeThread					0x482e8408
#define HASH_RtlExitUserThread						0x8e492b88

#define HASH_CreateEventW						0x5d01f1b2
#define HASH_CreateThread						0x7f08f451
#define HASH_GetThreadContext						0xeba2cfc2
#define HASH_VirtualProtect						0x844ff18d
#define HASH_WaitForSingleObject					0xeccda1ba
#define HASH_SetEvent							0x877ebbd3
#define HASH_QueueUserAPC						0x76c0c4bd
#define HASH_TerminateThread						0x87ae6a46
#define HASH_CloseHandle						0x3870ca07
#define HASH_LoadLibraryA						0x5fbff0fb

#define HASH_SystemFunction032						0xcccf3585

#define HASH_BCryptOpenAlgorithmProvider                		0x2a15dfdd
#define HASH_BCryptGenRandom						0x3a73c634
#define HASH_BCryptCloseAlgorithmProvider               		0xfcd0cdc1

#define HASH_Kernel32							0x6ddb9555
#define HASH_Ntdll							0x22d3b5ed

#define SPOOF_0(func) Spoofer(func, 0, 0, 0, 0, 0, 0, 0, 0)
#define SPOOF_1(func, arg1) Spoofer(func, arg1, 0, 0, 0, 0, 0, 0, 0)
#define SPOOF_2(func, arg1, arg2) Spoofer(func, arg1, arg2, 0, 0, 0, 0, 0, 0)
#define SPOOF_3(func, arg1, arg2, arg3) Spoofer(func, arg1, arg2, arg3, 0, 0, 0, 0, 0)
#define SPOOF_4(func, arg1, arg2, arg3, arg4) Spoofer(func, arg1, arg2, arg3, arg4, 0, 0, 0, 0)
#define SPOOF_5(func, arg1, arg2, arg3, arg4, arg5) Spoofer(func, arg1, arg2, arg3, arg4, arg5, 0, 0, 0)
#define SPOOF_6(func, arg1, arg2, arg3, arg4, arg5, arg6) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0)
#define SPOOF_7(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, 0)
#define SPOOF_8(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) Spoofer(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#define GET_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define SPOOF(...) GET_MACRO(__VA_ARGS__, SPOOF_8, SPOOF_7, SPOOF_6, SPOOF_5, SPOOF_4, SPOOF_3, SPOOF_2, SPOOF_1, SPOOF_0)(__VA_ARGS__)


typedef HMODULE	(WINAPI* fnLoadLibraryA)					(LPCSTR);
typedef BOOL	(WINAPI* fnCheckGadget)						(PVOID);
typedef DWORD	(WINAPI* fnWaitForSingleObject)					(HANDLE, DWORD);

typedef struct _USTRING
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING;

typedef struct _SECTION_INFO {
	PVOID pAddr;
	DWORD dwSize;
} SECTION_INFO, * PSECTION_INFO;

typedef struct _PRM  {
	const void* trampoline;     
	void* function;             
	void* rbx;                  
} PRM, * PPRM;

typedef struct _WIN_MODULE {
	PVOID pKernel32;
	PVOID pNtdll;
	PVOID pCryptsp;
	PVOID pBcrypt;
} WIN_MODULE, * PWIN_MODULE;

typedef struct _WIN_FUNCTION {
	PVOID pTpReleaseCleanupGroupMembers;
	PVOID pNtContinue;
	PVOID pNtTestAlert;
	PVOID pNtAlertResumeThread;
	PVOID pRtlExitUserThread;

	PVOID pCreateEventW;
	PVOID pCreateThread;
	PVOID pGetThreadContext;
	PVOID pVirtualProtect;
	PVOID pWaitForSingleObject;
	PVOID pSetEvent;
	PVOID pQueueUserAPC;
	PVOID pTerminateThread;
	PVOID pCloseHandle;
	PVOID pLoadLibraryA;

	PVOID pSystemFunction032;

	PVOID pBCryptOpenAlgorithmProvider;
	PVOID pBCryptGenRandom;
	PVOID pBCryptCloseAlgorithmProvider;
} WIN_FUNCTION, * PWIN_FUNCTION;

typedef struct _WIN_GADGET {
	PVOID pJmpRbx;
	PVOID pJmpRax;
} WIN_GADGET, * PWIN_GADGET;

typedef struct _INSTANCE {
	WIN_MODULE wModule;
	WIN_FUNCTION wFunction;
} INSTANCE, * PINSTANCE;

VOID			KrakenSleep(DWORD dwSleepTime);
extern PVOID		SpoofStub(PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID);
PVOID			Spoofer(PVOID pFunction, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8);
PVOID			FindGadget(PVOID pModule, fnCheckGadget CallbackCheck);
BOOL			fnGadgetJmpRbx(PVOID pAddr);
BOOL			fnGadgetJmpRax(PVOID pAddr);
BOOL			TakeSectionInfo(PSECTION_INFO SecInfo);
VOID			InitInstance(PINSTANCE Inst);
VOID			MyMemncpy(PBYTE dst, PBYTE src, DWORD dwSize);
