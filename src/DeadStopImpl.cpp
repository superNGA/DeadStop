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

// Signal Handlers...
#include "SignalHandler/SignalHandler.h"

// Util...
#include "Util/Assertion/Assertion.h"
#include "Util/Terminal/Terminal.h"

// Disassebler...
#include "../lib/IDASM/Include/INSANE_DisassemblerAMD64.h"

// Mind this...
using namespace DeadStop;




///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop_t::DeadStop_t()
{
    m_bInitialized = false;
    m_szDumpFilePath.clear();
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_t::Initialize(const char* szDumpFilePath, int iAsmDumpRangeinBytes, int iStringDumpSize, int iCallStackDepth)
{
    assertion(m_bInitialized == false && "DeadStop is already initialized.");
    assertion(szDumpFilePath != nullptr && "Invalid dump file path");
    assertion(iAsmDumpRangeinBytes > 0 && "Invalid assembly dump range");
    assertion(iAsmDumpRangeinBytes < 0x1000 && "Too big dump range");
    assertion(iStringDumpSize >= 0 && "Invalid string dump size. Must be more than 0");
    assertion(iCallStackDepth > 0 && "Invalid call stack depth");


    m_iStringDumpSize = iStringDumpSize;
    m_iAsmDumpRange   = iAsmDumpRangeinBytes;
    m_iCallStackDepth = iCallStackDepth;


    // Starting up submodules...
    if(InsaneDASM64::Initialize() != InsaneDASM64::IDASMErrorCode_Success)
        return ErrCode_FailedToStartSubModules;


    // File path must be valid.
    if(szDumpFilePath == nullptr)
        return ErrCode_FailedInit;


    m_szDumpFilePath = szDumpFilePath;


    // Setting up sigaction struct.
    {
        memset(&m_sigAction, 0, sizeof(struct sigaction));
        m_sigAction.sa_flags     = SA_SIGINFO; // so we get addition signal information.
        m_sigAction.sa_sigaction = MasterSignalHandler;

        // Register our handler.
        sigaction(SIGSEGV, &m_sigAction, nullptr); // Segment fault.
        sigaction(SIGILL,  &m_sigAction, nullptr); // Illegal instruction.
        sigaction(SIGTRAP, &m_sigAction, nullptr); // breakpoint ( int3 )
        sigaction(SIGABRT, &m_sigAction, nullptr); // abort() / assertion fail.
        sigaction(SIGFPE,  &m_sigAction, nullptr); // devide by zero.
        sigaction(SIGBUS,  &m_sigAction, nullptr); // hardware memory error, bad mmap.
    }


    m_bInitialized   = true;
    return ErrCodes_t::ErrCode_Success;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_t::Uninitialize()
{
    // Closing submodules...
    InsaneDASM64::UnInitialize();


    return ErrCodes_t::ErrCode_Success;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop_t::IsInitialized() const
{
    return m_bInitialized;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
const std::string& DeadStop_t::GetDumpFilePath() const
{
    return m_szDumpFilePath;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int DeadStop_t::GetAsmDumpRange() const
{
    return m_iAsmDumpRange;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int DeadStop_t::GetStringDumpSize() const
{
    return m_iStringDumpSize;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int DeadStop_t::GetCallStackDepth() const
{
    return m_iCallStackDepth;
}
