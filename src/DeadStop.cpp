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
ErrCodes_t DeadStop::Initialize(const char* szDumpFilePath, int iAsmDumpRangeInBytes, int iStringDumpSize, int iCallStackDepth)
{
    return DeadStop_t::GetInstance().Initialize(szDumpFilePath, iAsmDumpRangeInBytes, iStringDumpSize, iCallStackDepth);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ErrCodes_t DeadStop::Uninitialize()
{
    return DeadStop_t::GetInstance().Uninitialize();
}
