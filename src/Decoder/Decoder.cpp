//=========================================================================
//                      Decoder
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Convert bytes to amd64 assembly
//-------------------------------------------------------------------------
#include "Decoder.h"


Decoder_t g_decoder;


///////////////////////////////////////////////////////////////////////////
enum DecoderSearchState_t : int
{
    DecoderSearchState_Invalid = -1,
    DecoderSearchState_LegacyPrefix = 0,
    DecoderSearchState_REX,
    DecoderSearchState_OpCode,
    DecoderSearchState_ModRM,
    DecoderSearchState_SID,
    DecoderSearchState_Displacement,
    DecoderSearchState_Immediate
};
///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void Decoder_t::Decode(std::vector<Byte>& vecOpCodes, std::vector<Decoder::Inst::Instruction_t>& vecOutput)
{
    vecOutput.clear();
    DecoderSearchState_t iSearchState = DecoderSearchState_t::DecoderSearchState_Invalid;


    for(Byte byte : vecOpCodes)
    {
            
    }
}
