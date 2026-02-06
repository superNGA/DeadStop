//=========================================================================
//                      DeadStop Implementation
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : DeadStop's core logic
//-------------------------------------------------------------------------
#include "DeadStopImpl.h"
#include <string.h>
#include <signal.h>
#include <bits/types/siginfo_t.h>

// Util...
#include "Util/Assertion/Assertion.h"
#include "Util/Terminal/Terminal.h"


// Mind this...
using namespace DeadStop;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void SignalHandler(int iSig, siginfo_t* pSigInfo, void* pContext)
{
    ucontext_t* pUContext = reinterpret_cast<ucontext_t*>(pContext);

    assertion(iSig == SIGSEGV && "Received signal is not for segfault.");

    LOG("Signal Index : %d, SigInfo : %p, Context : %p", iSig, pSigInfo, pContext);

    // struct _sigfault* pSegFaultInfo = reinterpret_cast<struct _sigfault*>(&pSigInfo->_sifields);

    LOG("Faulted @ adrs : %p, adrs LSB: %p", pSigInfo->si_addr, pSigInfo->si_addr_lsb);
    LOG("si_lower : %p", pSigInfo->si_lower);
    LOG("si_upper : %p", pSigInfo->si_upper);
    LOG("si_pkey  : %p", pSigInfo->si_pkey);

    abort();
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop_t::DeadStop_t()
{
    m_bInitialized = false;
    m_szDumpFilePath.clear();
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_t::Initialize(const char* szDumpFilePath)
{
    assertion(m_bInitialized == false && "DeadStop is already initialized.");
    assertion(szDumpFilePath != nullptr && "Invalid dump file path");


    // File path must be valid.
    if(szDumpFilePath == nullptr)
        return ErrCode_FailedInit;


    m_szDumpFilePath = szDumpFilePath;


    // Setting up sigaction struct.
    {
        memset(&m_sigAction, 0, sizeof(struct sigaction));
        m_sigAction.sa_flags     = SA_SIGINFO; // so we get addition signal information.
        m_sigAction.sa_sigaction = SignalHandler;

        // Register our handler.
        sigaction(SIGSEGV, &m_sigAction, nullptr);
    }


    m_bInitialized   = true;
    return ErrCodes_t::ErrCode_Success;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_t::Uninitialize()
{
    return ErrCodes_t::ErrCode_Success;
}
