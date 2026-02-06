//=========================================================================
//                      Signal Handler
//=========================================================================
// by      : INSANE
// created : 06/02/2026
//
// purpose : Handler roughly all common signals received from OS.
//-------------------------------------------------------------------------
#pragma once
#include "../../Include/Alias.h"
#include "../../Include/DeadStop.h"
#include <csignal>



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
namespace DEADSTOP_NAMESPACE
{
    void MasterSignalHandler(int iSignalID, siginfo_t* pSigInfo, void* pContext);
}
