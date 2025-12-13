//=========================================================================
//                      Instruction_t
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Holds information about one complete amd64 assembly instruction
//-------------------------------------------------------------------------
#pragma once

#include "LegacyPrefix_t.h"
#include "REX_t.h"
#include "OpCode_t.h"
#include "ModRM_t.h"
#include "SID_t.h"
#include "Displacement_t.h"
#include "Immediate_t.h"


///////////////////////////////////////////////////////////////////////////
namespace Decoder::Inst
{

struct Instruction_t
{
    Instruction_t() : 
    m_legacyPrefix(),
    m_opCodes     (),
    m_rex         (),
    m_modRM       (),
    m_sid         (),
    m_displacement(),
    m_immediate   ()
    {}


    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    inline void Clear()
    {
        m_legacyPrefix.Clear();
        m_rex.Clear();

        for(int i = 0; i < MAX_OPCODES; i++)
            m_opCodes[i].Clear();
        m_nOpCodes = 0;

        m_modRM.Clear();
        m_sid.Clear();
        m_displacement.Clear();
        m_immediate.Clear();
    }


    LegacyPrefix_t m_legacyPrefix;
    REX_t          m_rex;
    int m_nOpCodes = 0;
    OpCode_t       m_opCodes[MAX_OPCODES];
    ModRM_t        m_modRM;
    SID_t          m_sid;
    Displacement_t m_displacement;
    Immediate_t    m_immediate;
};

}
///////////////////////////////////////////////////////////////////////////
