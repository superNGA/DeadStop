//=========================================================================
//                      DeadStop Implementation
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : DeadStop's core logic
//-------------------------------------------------------------------------
#include "DeadStopImpl.h"


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
ErrCodes_t DeadStop_t::Initialize(const char* szDumpFilePath)
{
    if(szDumpFilePath == nullptr)
        return ErrCode_FailedInit;

    m_szDumpFilePath = szDumpFilePath;

    return ErrCodes_t::ErrCode_Success;
}
