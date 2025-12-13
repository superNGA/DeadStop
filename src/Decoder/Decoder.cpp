//=========================================================================
//                      Decoder
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Convert bytes to amd64 assembly
//-------------------------------------------------------------------------
#include "Decoder.h"
#include "DecoderDefs/Instruction_t.h"
#include "DecoderRules.h"
#include "DecoderHelper/InstructionType/InstructionType.h"

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


    Decoder::Inst::Instruction_t inst;
    for(Byte byte : vecOpCodes)
    {
        // If is legacy prefix and we can store legacy prefix, then store.
        if(Decoder::g_instTypeHandler.IsLegacyPrefix(byte) == true && inst.m_legacyPrefix.CanStorePrefix() == true)
        {
            inst.m_legacyPrefix.PushPrefix(byte);
            continue; // Done for this byte.
        }
        else if(Decoder::g_instTypeHandler.IsREX(byte) == true)
        {
            // NOTE : If multiple consequtive REX appear, we will store the last one this way.
            inst.m_rex.Store(byte);
            continue;
        }
        else if(Decoder::g_instTypeHandler.IsOpCode(byte) == true)
        {
            Decoder::Inst::OpCode_t* pOpCode = Decoder::g_instTypeHandler.GetOpCode(byte);

            if(pOpCode == nullptr)
            {
                printf("Bad OpCode : 0x%02X\n", byte);
                continue;
            }
                

            if(inst.m_nOpCodes >= MAX_OPCODES)
            {
                printf("Too many opcodes!\n");
                continue;
            }

            inst.m_opCodes[inst.m_nOpCodes] = *pOpCode;
            inst.m_nOpCodes++;
            continue;
        }
    }
}
