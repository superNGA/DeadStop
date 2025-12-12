//=========================================================================
//                      Decoder
//=========================================================================
// by      : INSANE
// created : 07/12/2025
//
// purpose : Convert bytes to amd64 assembly
//-------------------------------------------------------------------------
#include <vector>
#include <cstdint>
#include "../Definitions.h"
#include "DecoderDefs/Instruction_t.h"


///////////////////////////////////////////////////////////////////////////
class Decoder_t
{
public:
    void Decode(std::vector<Byte>& vecOpCodes, std::vector<Decoder::Inst::Instruction_t>& vecOutput);

private:
    uint16_t m_instTypeLUT[0xFF];

};
extern Decoder_t g_decoder;
///////////////////////////////////////////////////////////////////////////
