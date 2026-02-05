//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : Log crashes with useful information.
//-------------------------------------------------------------------------
#include "../Include/DeadStop.h"
#include <windows.h>
#include "Util/Terminal/Terminal.h"
#include "DeadStopImpl.h"


// Mind this...
using namespace DeadStop;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
LONG CALLBACK CrashHandler(PEXCEPTION_POINTERS pException)
{
    FAIL_LOG("Crash found!");

    PEXCEPTION_RECORD pExpRecords = pException->ExceptionRecord;
    PCONTEXT          pContext    = pException->ContextRecord;

    LOG("Code : 0x%08lX, iFlags : %lu, Adrs : %p\n", pExpRecords->ExceptionCode, pExpRecords->ExceptionFlags, pExpRecords->ExceptionAddress);

    return EXCEPTION_CONTINUE_SEARCH;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop::Initialize(const char* szDumpFilePath)
{
    DeadStop_t::GetInstance().Initialize(szDumpFilePath);

    void* hExHandler = AddVectoredExceptionHandler(1, CrashHandler);

    // Did we fail to add VXH
    if(hExHandler == nullptr)
        return ErrCodes_t::ErrCode_FailedInit;


    g_exHandlerInfo.m_hExHandler = hExHandler;

    return ErrCodes_t::ErrCode_Success;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop::Uninitialize()
{
    return ErrCode_Success;
}
