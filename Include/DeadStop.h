//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : Log crashes with useful information.
//-------------------------------------------------------------------------
#pragma once
#include "Alias.h"


namespace DEADSTOP_NAMESPACE
{
    enum ErrCodes_t
    {
        ErrCode_Invalid = -1,
        ErrCode_Success = 0,
        ErrCode_FailedInit,
        ErrCode_FailedToStartSubModules,

        ErrCode_Count
    };


    ErrCodes_t Initialize(const char* szDumpFilePath, int iAsmDumpRangeInBytes);
    ErrCodes_t Uninitialize();
    const char* GetErrorMessage(ErrCodes_t iErrCode);
}
