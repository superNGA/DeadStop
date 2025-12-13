//=========================================================================
//                      OpCode_t
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Holds upto 3 OpCodes
//-------------------------------------------------------------------------
#pragma once
#include "../../Definitions.h"
#include <system_error>
#include <utility>


///////////////////////////////////////////////////////////////////////////
namespace Decoder::Inst
{


///////////////////////////////////////////////////////////////////////////
enum OpCodeAddresingMethod_t : Byte
{
    OpCodeAddresingMethod_Invalid = 0xFF,

    OpCodeAddresingMethod_A = 'A',
    OpCodeAddresingMethod_B = 'B',
    OpCodeAddresingMethod_C = 'C',
    OpCodeAddresingMethod_D = 'D',
    OpCodeAddresingMethod_E = 'E',
    OpCodeAddresingMethod_F = 'F',
    OpCodeAddresingMethod_G = 'G',
    OpCodeAddresingMethod_H = 'H',
    OpCodeAddresingMethod_I = 'I',
    OpCodeAddresingMethod_J = 'J',
    // OpCodeAddresingMethod_K = 'K',
    OpCodeAddresingMethod_L = 'L',
    OpCodeAddresingMethod_M = 'M',
    OpCodeAddresingMethod_N = 'N',
    OpCodeAddresingMethod_O = 'O',
    OpCodeAddresingMethod_P = 'P',
    OpCodeAddresingMethod_Q = 'Q',
    OpCodeAddresingMethod_R = 'R',
    OpCodeAddresingMethod_S = 'S',
    // OpCodeAddresingMethod_T = 'T',
    OpCodeAddresingMethod_U = 'U',
    OpCodeAddresingMethod_V = 'V',
    OpCodeAddresingMethod_W = 'W',
    OpCodeAddresingMethod_X = 'X',
    OpCodeAddresingMethod_Y = 'Y',

    OpCodeAddresingMethod_Register_AL,
    OpCodeAddresingMethod_Register_AX,
    OpCodeAddresingMethod_Register_eAX,
    OpCodeAddresingMethod_Register_rAX,
    OpCodeAddresingMethod_Register_BX,
    OpCodeAddresingMethod_Register_eBX,
    OpCodeAddresingMethod_Register_rBX,
    OpCodeAddresingMethod_Register_CX,
    OpCodeAddresingMethod_Register_eCX,
    OpCodeAddresingMethod_Register_rCX,
    OpCodeAddresingMethod_Register_DX,
    OpCodeAddresingMethod_Register_eDX,
    OpCodeAddresingMethod_Register_rDX,
    OpCodeAddresingMethod_Register_SP,
    OpCodeAddresingMethod_Register_eSP,
    OpCodeAddresingMethod_Register_rSP,
    OpCodeAddresingMethod_Register_DI,
    OpCodeAddresingMethod_Register_eDI,
    OpCodeAddresingMethod_Register_rDI,
    OpCodeAddresingMethod_Register_BP,
    OpCodeAddresingMethod_Register_eBP,
    OpCodeAddresingMethod_Register_rBP,
};
///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
enum OpCodeOperandType_t : Byte
{
    OpCodeOperandType_Invalid = 0xFF,

    OpCodeOperandType_a = 0x00,
    OpCodeOperandType_b ,
    OpCodeOperandType_c ,
    OpCodeOperandType_d ,
    OpCodeOperandType_dq,
    OpCodeOperandType_p ,
    OpCodeOperandType_pd,
    OpCodeOperandType_pi,
    OpCodeOperandType_ps,
    OpCodeOperandType_q ,
    OpCodeOperandType_qq,
    OpCodeOperandType_s ,
    OpCodeOperandType_sd,
    OpCodeOperandType_ss,
    OpCodeOperandType_si,
    OpCodeOperandType_v ,
    OpCodeOperandType_w ,
    OpCodeOperandType_x ,
    OpCodeOperandType_y ,
    OpCodeOperandType_z ,

    OpCodeOperantType_Count
};
///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
enum OpCodeSuperScripts_t : int32_t
{
    OpCodeSuperScripts_None = -1,
    OpCodeSuperScripts_1A = 0,    // Use ModR/M byte's REG as OpCode extension
    OpCodeSuperScripts_1B,        // Use the OpCode 0F0B, 0FB9H, 0FFFH or D6 when deliberately trying to generate an invalid opcode exception (#UD).
    OpCodeSuperScripts_1C,        // Use ModR/M byte's REG as OpCode extension ( use table A-6. )
    OpCodeSuperScripts_i64,       // Not available in 64 bit mode.
    OpCodeSuperScripts_o64,       // Instruction is only available in 64 bit mode.
    OpCodeSuperScripts_d64,       // In 64 bit mode, the operand size WILL be 64 bits.
    OpCodeSuperScripts_f64,       // Operand size is forced to be 64 bit in 64 bit mode.
    OpCodeSuperScripts_v,         // VEX forms only exists.
    OpCodeSuperScripts_v1,        // VEX128 & SSE forms only exist (no VEX256), when can’t be inferred from the data size.

    OpCodeSuperScript_Count
};
///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
struct OpCode_t
{
    // Default Constructor...
    OpCode_t() : 
        m_szOperation                   ( nullptr                       ),
        m_iByte                         ( 0x00                          ),
        m_nOperands                     ( 0                             ),
        m_iOpCodeSuperScript            ( OpCodeSuperScripts_None       ),
        m_iOperandLeftAddressingMethod  ( OpCodeAddresingMethod_Invalid ),
        m_iOperandLeftType              ( OpCodeOperandType_Invalid     ),
        m_iOperandRightAddressingMethod ( OpCodeAddresingMethod_Invalid ),
        m_iOperandRightType             ( OpCodeOperandType_Invalid     )
    {}


    // Constructor...
    OpCode_t(const char* szOpCodeName, int nOperands, Byte iByte, 
             OpCodeSuperScripts_t    iSuperScript           = OpCodeSuperScripts_None,
             OpCodeAddresingMethod_t iAddressingMethodLeft  = OpCodeAddresingMethod_Invalid,
             OpCodeOperandType_t     iOperandTypeLeft       = OpCodeOperandType_Invalid,
             OpCodeAddresingMethod_t iAddressingMethodRight = OpCodeAddresingMethod_Invalid,
             OpCodeOperandType_t     iOperandTypeRight      = OpCodeOperandType_Invalid) :

    m_szOperation                   ( szOpCodeName           ),
    m_iByte                         ( iByte                  ),
    m_nOperands                     ( nOperands              ),
    m_iOpCodeSuperScript            ( iSuperScript           ),
    m_iOperandLeftAddressingMethod  ( iAddressingMethodLeft  ),
    m_iOperandLeftType              ( iOperandTypeLeft       ),
    m_iOperandRightAddressingMethod ( iAddressingMethodRight ),
    m_iOperandRightType             ( iOperandTypeRight      )
    {}


    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    void operator=(const OpCode_t& other)
    {
        m_szOperation                   = other.m_szOperation;
        m_nOperands                     = other.m_nOperands;
        m_iByte                         = other.m_iByte;
        m_iOpCodeSuperScript            = other.m_iOpCodeSuperScript;
        m_iOperandLeftAddressingMethod  = other.m_iOperandLeftAddressingMethod;
        m_iOperandLeftType              = other.m_iOperandLeftType;
        m_iOperandRightAddressingMethod = other.m_iOperandRightAddressingMethod;
        m_iOperandRightType             = other.m_iOperandRightType;
    }


    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    inline void Clear()
    {
        m_szOperation                   = nullptr;
        m_nOperands                     = 0;
        m_iByte                         = 0; // 00h is a valid opcode, so this doesn't help at all in clearing.
        m_iOpCodeSuperScript            = OpCodeSuperScripts_None;
        m_iOperandLeftAddressingMethod  = OpCodeAddresingMethod_t::OpCodeAddresingMethod_Invalid;
        m_iOperandLeftType              = OpCodeOperandType_t::OpCodeOperandType_Invalid;
        m_iOperandRightAddressingMethod = OpCodeAddresingMethod_t::OpCodeAddresingMethod_Invalid;
        m_iOperandRightType             = OpCodeOperandType_t::OpCodeOperandType_Invalid;
    }


    // Fields...
    const char*             m_szOperation;
    int32_t                 m_nOperands;
    Byte                    m_iByte;
    OpCodeSuperScripts_t    m_iOpCodeSuperScript;

    // Left operand...
    OpCodeAddresingMethod_t m_iOperandLeftAddressingMethod;
    OpCodeOperandType_t     m_iOperandLeftType;

    // Right operand...
    OpCodeAddresingMethod_t m_iOperandRightAddressingMethod;
    OpCodeOperandType_t     m_iOperandRightType;
};
///////////////////////////////////////////////////////////////////////////


}
///////////////////////////////////////////////////////////////////////////
