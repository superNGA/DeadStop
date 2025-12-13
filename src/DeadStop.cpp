//=========================================================================
//                      DeadStop
//=========================================================================
// by      : INSANE
// created : 11/12/2025
//
// purpose : Logs crashes / exceptions :)
//-------------------------------------------------------------------------
#include "DeadStop.h"
#include "Decoder/DecoderHelper/InstructionType/InstructionType.h"


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop::Initialize()
{
    if(Decoder::g_instTypeHandler.Initialize() == false)
    {
        return false;
    }


    return true;
}
