//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : Log crashes with useful information.
//-------------------------------------------------------------------------
#include "../Include/DeadStop.h"
#include "DeadStopImpl.h"


// Mind this...
using namespace DeadStop;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_InitializeEx(const char* szDumpFilePath, int iAsmDumpRangeInBytes, int iStringDumpSize, int iCallStackDepth, int iSignatureSize)
{
    return DeadStop_t::GetInstance().Initialize(szDumpFilePath, iAsmDumpRangeInBytes, iStringDumpSize, iCallStackDepth, iSignatureSize);
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_Initialize(const char* szDumpFilePath)
{
    return DeadStop_t::GetInstance().Initialize(szDumpFilePath, 50, 10, 3, 15);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop_Uninitialize()
{
    return DeadStop_t::GetInstance().Uninitialize();
}
