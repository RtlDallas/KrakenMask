#include "struct.h"

#include <bcrypt.h>

#pragma comment (lib, "Bcrypt.lib")

#define TEXT_HASH	0xb80c0d8
#define SECTION_HEADER_SIZE 40

VOID KrakenSleep									(DWORD dwSleepTime);

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

extern PVOID			SpoofStub						(PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID);

typedef NTSTATUS		(NTAPI* fnNtAlertResumeThread)				(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS		(NTAPI* fnNtSignalAndWaitForSingleObject)		(HANDLE ObjectToSignal, HANDLE WaitableObject, BOOLEAN Altertable, PLARGE_INTEGER Time);

PBYTE FindGadget		(PVOID base, DWORD size, const BYTE* pattern, DWORD patternSize);
PVOID Spoofer			(PVOID pFunction, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8);
VOID GenerateKey		(BYTE* key, DWORD keySize);
DWORD HashStringDjb2A		(LPCSTR String);
BOOL TakeSectionInfo		(PSECTION_INFO SecInfo);
PVOID GetNtdllAddr		();

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
