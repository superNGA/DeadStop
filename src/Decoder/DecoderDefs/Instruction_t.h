//=========================================================================
//                      Instruction_t
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Holds information about one complete amd64 assembly instruction
//-------------------------------------------------------------------------


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
    LegacyPrefix_t m_legacyPrefix;
    REX_t          m_rex;
    OpCode_t       m_opCodes;
    ModRM_t        m_modRM;
    SID_t          m_sid;
    Displacement_t m_displacement;
    Immediate_t    m_immediate;
};

}
///////////////////////////////////////////////////////////////////////////
