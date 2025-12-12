//=========================================================================
//                      Instruction Type
//=========================================================================
// by      : INSANE
// created : 11/12/2025
//
// purpose : Holds a Look Up Table from 0x00 to 0xff, to check byte type in O(1) time.
//-------------------------------------------------------------------------
#include "InstructionType.h"

#include <string.h>



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void Decoder::InstructionType_t::Initialize()
{
    if(m_bInstTypeLUTInit == false)
    {
        m_bInstTypeLUTInit = _InitInstTypeLUT();
    }


    if(m_bOneByteOpCodeLUTInit == false)
    {
        m_bOneByteOpCodeLUTInit = _InitOneByteOpCodeLUT();
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool Decoder::InstructionType_t::_InitInstTypeLUT()
{
    memset(m_instTypeLUT, 0, sizeof(m_instTypeLUT));

    
    // Legacy Prefix...
    {
        // Group 1 Legacy Prefix...
        m_instTypeLUT[0xF0] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0xF2] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0xF3] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;

        
        // Group 2 Legacy Prefix...
        m_instTypeLUT[0x2E] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0x36] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0x3E] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0x26] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0x64] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;
        m_instTypeLUT[0x65] |= InstTypes_t::InstTypes_LegacyPrefixGrp1;


        // Group 3 Legacy Prefix...
        m_instTypeLUT[0x66] |= InstTypes_t::InstTypes_LegacyPrefixGrp3;


        // Group 4 Legacy Prefix...
        m_instTypeLUT[0x67] |= InstTypes_t::InstTypes_LegacyPrefixGrp4;
    }


    // REX... ( 0x40 - 0x4F, i.e. all bytes with pattern '0100 xxxx' )
    {
        for(size_t i = 0x40; i <= 0x4F; i++)
            m_instTypeLUT[i] |= InstTypes_t::InstTypes_REX;
    }


    // Op Codes... ( everything except REX & legacy prefixies )
    {
        for(size_t i = 0x00; i <= 0xFF; i++)
        {
            if(m_instTypeLUT[i] == 0)
                m_instTypeLUT[i] |= InstTypes_t::InstTypes_OpCode;
        }
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool Decoder::InstructionType_t::_InitOneByteOpCodeLUT()
{
    // Set all to default...
    for(size_t i = 0; i <= 0xFF; i++)
    {
        m_oneByteOpCodeLUT[i] = Decoder::Inst::OpCode_t();
    }
    
    using namespace Inst;

    // Fill in OpCodes one by one. ( pain )
    m_oneByteOpCodeLUT[0x00] = Inst::OpCode_t("ADD", 2, 0x00,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x01] = Inst::OpCode_t("ADD", 2, 0x01,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x02] = Inst::OpCode_t("ADD", 2, 0x02,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x03] = Inst::OpCode_t("ADD", 2, 0x03,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x04] = Inst::OpCode_t("ADD", 2, 0x04,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x05] = Inst::OpCode_t("ADD", 2, 0x05,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x06] = Inst::OpCode_t("PUSH", 1, 0x06,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x07] = Inst::OpCode_t("POP", 1, 0x07,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x08] = Inst::OpCode_t("OR", 2, 0x08,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x09] = Inst::OpCode_t("OR", 2, 0x09,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x0A] = Inst::OpCode_t("OR", 2, 0x0A,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x0B] = Inst::OpCode_t("OR", 2, 0x0B,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x0C] = Inst::OpCode_t("OR", 2, 0x0C,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x0D] = Inst::OpCode_t("OR", 2, 0x0D,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x0E] = Inst::OpCode_t("PUSH", 1, 0x0E,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x0F] = Inst::OpCode_t("POP", 1, 0x0F,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x10] = Inst::OpCode_t("ADC", 2, 0x10,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x11] = Inst::OpCode_t("ADC", 2, 0x11,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x12] = Inst::OpCode_t("ADC", 2, 0x12,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x13] = Inst::OpCode_t("ADC", 2, 0x13,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x14] = Inst::OpCode_t("ADC", 2, 0x14,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x15] = Inst::OpCode_t("ADC", 2, 0x15,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x16] = Inst::OpCode_t("PUSH", 1, 0x16,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x17] = Inst::OpCode_t("POP", 1, 0x17,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x18] = Inst::OpCode_t("SBB", 2, 0x18,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x19] = Inst::OpCode_t("SBB", 2, 0x19,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x1A] = Inst::OpCode_t("SBB", 2, 0x1A,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x1B] = Inst::OpCode_t("SBB", 2, 0x1B,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x1C] = Inst::OpCode_t("SBB", 2, 0x1C,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x1D] = Inst::OpCode_t("SBB", 2, 0x1D,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x1E] = Inst::OpCode_t("PUSH", 1, 0x1E,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x1F] = Inst::OpCode_t("POP", 1, 0x1F,
        OpCodeSuperScripts_i64,
        OpCodeAddresingMethod_S, OpCodeOperandType_w);

    m_oneByteOpCodeLUT[0x20] = OpCode_t("AND", 2, 0x20,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x21] = OpCode_t("AND", 2, 0x21,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x22] = OpCode_t("AND", 2, 0x22,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x23] = OpCode_t("AND", 2, 0x23,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x24] = OpCode_t("AND", 2, 0x24,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x25] = OpCode_t("AND", 2, 0x25,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x26] = OpCode_t("ES", 0, 0x26,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x27] = OpCode_t("DAA", 0, 0x27,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x28] = OpCode_t("SUB", 2, 0x28,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x29] = OpCode_t("SUB", 2, 0x29,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x2A] = OpCode_t("SUB", 2, 0x2A,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x2B] = OpCode_t("SUB", 2, 0x2B,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x2C] = OpCode_t("SUB", 2, 0x2C,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x2D] = OpCode_t("SUB", 2, 0x2D,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x2E] = OpCode_t("CS", 0, 0x2E,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x2F] = OpCode_t("DAS", 0, 0x2F,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x30] = OpCode_t("XOR", 2, 0x30,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x31] = OpCode_t("XOR", 2, 0x31,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x32] = OpCode_t("XOR", 2, 0x32,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x33] = OpCode_t("XOR", 2, 0x33,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x34] = OpCode_t("XOR", 2, 0x34,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x35] = OpCode_t("XOR", 2, 0x35,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x36] = OpCode_t("SS", 0, 0x36,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x37] = OpCode_t("AAA", 0, 0x37,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x38] = OpCode_t("CMP", 2, 0x38,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_b,
        OpCodeAddresingMethod_G, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x39] = OpCode_t("CMP", 2, 0x39,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_E, OpCodeOperandType_v,
        OpCodeAddresingMethod_G, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x3A] = OpCode_t("CMP", 2, 0x3A,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_b,
        OpCodeAddresingMethod_E, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x3B] = OpCode_t("CMP", 2, 0x3B,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_G, OpCodeOperandType_v,
        OpCodeAddresingMethod_E, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x3C] = OpCode_t("CMP", 2, 0x3C,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_AL, OpCodeOperandType_b,
        OpCodeAddresingMethod_I, OpCodeOperandType_b);

    m_oneByteOpCodeLUT[0x3D] = OpCode_t("CMP", 2, 0x3D,
        OpCodeSuperScripts_None,
        OpCodeAddresingMethod_Register_eAX, OpCodeOperandType_v,
        OpCodeAddresingMethod_I, OpCodeOperandType_v);

    m_oneByteOpCodeLUT[0x3E] = OpCode_t("DS", 0, 0x3E,
        OpCodeSuperScripts_None);

    m_oneByteOpCodeLUT[0x3F] = OpCode_t("AAS", 0, 0x3F,
        OpCodeSuperScripts_None);

    return true;
}
