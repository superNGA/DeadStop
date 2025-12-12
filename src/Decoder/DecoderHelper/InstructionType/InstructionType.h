//=========================================================================
//                      Instruction Type
//=========================================================================
// by      : INSANE
// created : 11/12/2025
//
// purpose : Holds a Look Up Table from 0x00 to 0xff, to check byte type in O(1) time.
//-------------------------------------------------------------------------
#include <cstdint>
#include "../../DecoderDefs/OpCode_t.h"


///////////////////////////////////////////////////////////////////////////
namespace Decoder
{

///////////////////////////////////////////////////////////////////////////
enum InstTypes_t : uint16_t
{
    InstTypes_LegacyPrefixGrp1 = (1 << 0),
    InstTypes_LegacyPrefixGrp2 = (1 << 1),
    InstTypes_LegacyPrefixGrp3 = (1 << 2),
    InstTypes_LegacyPrefixGrp4 = (1 << 3),

    InstTypes_REX              = (1 << 4),

    InstTypes_OpCode           = (1 << 5)

    // Not complete...
};
///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
class InstructionType_t
{
public:
    void Initialize();

private:
    bool _InitInstTypeLUT();
    bool m_bInstTypeLUTInit = false;

    uint16_t m_instTypeLUT[0x100]; // 256 elements


    bool _InitOneByteOpCodeLUT();
    bool m_bOneByteOpCodeLUTInit = false;
    Decoder::Inst::OpCode_t m_oneByteOpCodeLUT[0x100];
};
///////////////////////////////////////////////////////////////////////////


}
///////////////////////////////////////////////////////////////////////////
