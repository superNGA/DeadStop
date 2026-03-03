//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : Log crashes with useful information.
//-------------------------------------------------------------------------
#pragma once


typedef enum ErrCodes_t
{
    ErrCode_Invalid = -1,
    ErrCode_Success = 0,
    ErrCode_FailedInit,
    ErrCode_FailedToStartSubModules,

    ErrCode_Count
} ErrCodes_t;


/* Initialize DeadStop and allow fine tunning settings. */
ErrCodes_t DeadStop_InitializeEx(
        const char* szDumpFilePath,
        int iAsmDumpRangeInBytes,
        int iStringDumpSize,
        int iCallStackDepth,
        int iSignatureSize);

/* Initialize DeadStop with default settings. */
ErrCodes_t DeadStop_Initialize(const char* szDumpFilePath);

/* Uninitialize DeadStop. */
ErrCodes_t DeadStop_Uninitialize();

/* Get string message for given ErrCode_t. */
const char* DeadStop_GetErrorMessage(ErrCodes_t iErrCode);
