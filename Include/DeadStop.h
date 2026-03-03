//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : Log crashes with useful information.
//-------------------------------------------------------------------------
#pragma once


enum ErrCodes_t
{
    ErrCode_Invalid = -1,
    ErrCode_Success = 0,
    ErrCode_FailedInit,
    ErrCode_FailedToStartSubModules,

    ErrCode_Count
};


ErrCodes_t InitializeEx(
        const char* szDumpFilePath,
        int iAsmDumpRangeInBytes,
        int iStringDumpSize,
        int iCallStackDepth,
        int iSignatureSize);

ErrCodes_t Initialize(const char* szDumpFilePath);

ErrCodes_t Uninitialize();
const char* GetErrorMessage(ErrCodes_t iErrCode);
