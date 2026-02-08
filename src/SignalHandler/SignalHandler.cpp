//=========================================================================
//                      Signal Handler
//=========================================================================
// by      : INSANE
// created : 06/02/2026
//
// purpose : Handler roughly all common signals received from OS.
//-------------------------------------------------------------------------
#include "SignalHandler.h"
#include <csignal>
#include "../DeadStopImpl.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <deque>

// Disassembler.
#include "../../lib/IDASM/Include/INSANE_DisassemblerAMD64.h"
#include "../../lib/IDASM/Include/Legacy/LegacyInst_t.h"
#include "../../lib/IDASM/Include/VEX/VEXInst_t.h"
#include "../../lib/IDASM/Include/EVEX/EVEXInst_t.h"
#include "../../lib/IDASM/Include/Standard/OpCodeDesc_t.h"

// Utility
#include "../Util/Assertion/Assertion.h"
#include "../Util/Terminal/Terminal.h"
#include "../Defs/MemRegion_t.h"


// Mind this...
using namespace DeadStop;




///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
namespace DEADSTOP_NAMESPACE
{
    // Global vars...
    MemRegionHandler_t g_memRegionHandler;
    siginfo_t*         g_pSigInfo = nullptr;
    ucontext_t*        g_pContext = nullptr;



    static bool DumpAssembly(std::fstream& hFile, int iSignalID, int iAsmDumpRangeInBytes);
    static bool GenerateDasmOutput(std::stringstream& ssOut, uintptr_t iStartAdrs, const std::vector<InsaneDASM64::Byte>& vecBytes, uintptr_t pCrashLocation);
    static const char* FindInstPointerToString(InsaneDASM64::Instruction_t& inst, uintptr_t iStartAdrs);
    static bool Analyze();
    static uintptr_t GetReturnAdrs(uintptr_t iStartPos);

    // Write to File.
    static void WriteSelfMaps       (std::fstream& hFile);
    static void DumpGeneralRegisters(std::fstream& hFile);
    static void DumpDateTime        (std::fstream& hFile);
    static void DoBranding          (std::fstream& hFile);
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void DeadStop::MasterSignalHandler(int iSignalID, siginfo_t* pSigInfo, void* pContext)
{
    // Is initialized?
    if(DeadStop_t::GetInstance().IsInitialized() == false)
        return; 

    std::fstream hFile(DeadStop_t::GetInstance().GetDumpFilePath(), std::ios::app);

    // Failed to open file?
    if(hFile.is_open() == false)
        return;


    // Writting date & time to file before writting anything else.
    hFile << "///////////////////////////////////////////////////////////////////////////\n";
    hFile << "///////////////////////////////////////////////////////////////////////////\n";
    DoBranding(hFile); hFile << "Fatal signal received, this program will terminate now.\n";
    DoBranding(hFile); hFile << "Starting log dump @ ";
    DumpDateTime(hFile);
    hFile << '\n';
    /* Prologue ends here */


    g_pContext = reinterpret_cast<ucontext_t*>(pContext);
    g_pSigInfo = pSigInfo;


    // Getting "this" process's memory regions.
    std::vector<MemRegion_t> vecSelfMaps; 
    if(g_memRegionHandler.InitializeFromFile("/proc/self/maps") == false) // Must not fail.
    {
        DoBranding(hFile); hFile << "Failed to open \"/proc/self/maps\". Cannot proceed any further.\n";
        return;
    }
    WriteSelfMaps(hFile);
    WIN_LOG("Got processes memory regions.");



    // Write the signal ID.
    switch(iSignalID)
    {
        case SIGSEGV:  DoBranding(hFile); hFile << "Signal received [ SIGSEGV ] i.e. Segfault\n"; break;
        case SIGILL:   DoBranding(hFile); hFile << "Signal received [ SIGILL ] i.e. Invalid Instruction\n"; break;
        case SIGTRAP:  DoBranding(hFile); hFile << "Signal Received [ SIGTRAP ] i.e. Trap Debugger\n"; break;
        case SIGABRT:  DoBranding(hFile); hFile << "Signal Received [ SIGABRT ] i.e. abort()\n"; break; 
        case SIGFPE:   DoBranding(hFile); hFile << "Signal Received [ SIGFPE ] i.e. Devide By Zero\n"; break;  
        case SIGBUS:   DoBranding(hFile); hFile << "Signal Received [ SIGBUS ] i.e. Hardware memory error, bad mmap.\n"; break; 

        default: assertion(false && "Invalid signal ID"); return;
    }


    // Dump all general purpose registers with their values.
    hFile << "\n\n";
    DumpGeneralRegisters(hFile);
    WIN_LOG("Dumped registers.");


    Analyze();

    hFile << "\n\n";
    // bool bAsmDumpWin = DumpAssembly(hFile, iSignalID, DeadStop_t::GetInstance().GetAsmDumpRange());


    // Epilogue
    DoBranding(hFile); hFile << "Log dump ended @ ";
    DumpDateTime(hFile);
    hFile << '\n';
    hFile << "///////////////////////////////////////////////////////////////////////////\n";
    hFile.close();
    exit(1);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::WriteSelfMaps(std::fstream& hFile)
{
    std::ifstream hMaps("/proc/self/maps");

    // If we can't open this, something must be really wrong.
    if(hMaps.is_open() == false)
        return;

    hFile << "------------------------------- Mapped Memory Regoins -------------------------------\n";

    std::string szLine;
    while(std::getline(hMaps, szLine))
    {
        hFile << szLine << std::endl;
    }

    hFile << "-------------------------------------------------------------------------------------\n\n\n";

    hMaps.close();
    return;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::DumpAssembly(std::fstream& hFile, int iSignalID, int iAsmDumpRangeInBytes)
{
    uintptr_t pCrashLocation = static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RIP]);


    // Does the crash location belong to the process?
    MemRegion_t memRegionCrashLoc(pCrashLocation - 10, pCrashLocation + 10);
    if(g_memRegionHandler.HasParentRegion(pCrashLocation) == false)
    {
        FAIL_LOG("Crash location [ %p ] is not a redable memory location. Cannot dump crash logs.", pCrashLocation);
        return false;
    }


    assertion(pCrashLocation > iAsmDumpRangeInBytes && "Invalid dump range or crash location?");
    assertion(iAsmDumpRangeInBytes > 0 && iAsmDumpRangeInBytes < 0x1000 && "invalid or Too big dump range");
    uintptr_t iAsmDumpStart = pCrashLocation - iAsmDumpRangeInBytes;
    uintptr_t iAsmDumpEnd   = pCrashLocation + iAsmDumpRangeInBytes;
    if(g_memRegionHandler.HasParentRegion(iAsmDumpStart, iAsmDumpEnd) == false)
    {
        hFile << "Some parts of the dump regions [ " << 
            std::hex << iAsmDumpStart << " - " << iAsmDumpEnd << 
            " ] can't be read, reducing dump region to 100 byte above & below\n";

        FAIL_LOG("Some parts of the dump regions [ 0x%016llX - 0x%016llX ] can't be read, reducing dump region to 100 byte above & below",
                iAsmDumpStart, iAsmDumpEnd);


        // Incase the initial memory region was smaller than 100 bytes and even
        // that wasn't in the process's memory, then no point in rechecking, something 
        // is fucked up real bad. Just leave now.
        if(iAsmDumpRangeInBytes > 100)
        {
            iAsmDumpStart = static_cast<intptr_t>(pCrashLocation) - 100; 
            iAsmDumpEnd   = pCrashLocation + 100;
        }
        

        // Checking aginst modified region.
        if(g_memRegionHandler.HasParentRegion(iAsmDumpStart, iAsmDumpEnd) == false)
        {
            hFile << "Dump region couldn't be read.\n";
            FAIL_LOG("Dump region couldn't be read.\n");
            return false;
        }
    }


    assertion(iAsmDumpRangeInBytes > 0 && "Invalid Dump Range");
    const int iAsmDumpRange = iAsmDumpRangeInBytes;


    // Collecting some bytes from crash location to disassembler.
    std::vector<InsaneDASM64::Byte> vecBytes;
    for(int i = -iAsmDumpRange; i < iAsmDumpRange; i++)
        vecBytes.push_back(*(reinterpret_cast<InsaneDASM64::Byte*>(pCrashLocation) + i));


    constexpr size_t MAX_DISASSEMBLING_ATTEMPS = 10;
    std::stringstream ssDasmOutput;
    bool bDasmSucceded = false;
    for(int iAttempt = 0; iAttempt < MAX_DISASSEMBLING_ATTEMPS; iAttempt++)
    {
        // Address of the first instruction.
        uintptr_t iStartAdrs = static_cast<uintptr_t>(
            static_cast<intptr_t>(pCrashLocation) - static_cast<intptr_t>(iAsmDumpRange) + static_cast<intptr_t>(iAttempt));


        ssDasmOutput.clear(); ssDasmOutput.str("");
        if(GenerateDasmOutput(ssDasmOutput, iStartAdrs, vecBytes, pCrashLocation) == true)
        {
            WIN_LOG("Disassembly verified.");
            bDasmSucceded = true;
            break;
        }

        // Remove the first element in case we fail.
        // NOTE : This takes O(n), cause some smart ass nigga decided that std::vector<bytes> is a good way to feed bytes 
        //        into a disassembler.
        vecBytes.erase(vecBytes.begin()); 

        FAIL_LOG("Disssembly Failed. Attempt number %d", iAttempt);
    }


    // We failed all disassembling attempts?
    if(bDasmSucceded == false)
    {
        DoBranding(hFile); hFile << "Disasesmlby Failed.\n";
        return false;
    }


    hFile << ssDasmOutput.str();
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::GenerateDasmOutput(
        std::stringstream& ssOut, uintptr_t iStartAdrs, const std::vector<InsaneDASM64::Byte>& vecBytes, uintptr_t pCrashLocation)
{
    // Decoder & Disassembler.
    std::vector<InsaneDASM64::Instruction_t> vecDecodedInst;
    std::vector<InsaneDASM64::DASMInst_t>    vecDisassembledInst; 
    ArenaAllocator_t allocator(8 * 1024); // 8 KiB arenas.


    // Decode...
    InsaneDASM64::IDASMErrorCode_t iDecodingErrCode = InsaneDASM64::Decode(vecBytes, vecDecodedInst, allocator);
    if(iDecodingErrCode != InsaneDASM64::IDASMErrorCode_t::IDASMErrorCode_Success)
    {
        ssOut << InsaneDASM64::GetErrorMessage(iDecodingErrCode) << std::endl;
        return false;
    }
    WIN_LOG("Decoding done.");


    // Disassemble...
    InsaneDASM64::IDASMErrorCode_t iDasmErrCode = InsaneDASM64::Disassemble(vecDecodedInst, vecDisassembledInst);
    if(iDasmErrCode != InsaneDASM64::IDASMErrorCode_t::IDASMErrorCode_Success)
    {
        ssOut << InsaneDASM64::GetErrorMessage(iDasmErrCode) << std::endl;
        return false;
    }
    WIN_LOG("Disassembing done.");


    // Disasesmbled data must be valid.
    if(vecDecodedInst.size() != vecDisassembledInst.size())
    {
        ssOut << "Decoded instructions and disassembled instruction count is not same.";
        ssOut << "Where did you got this dog crap disassembler from?" << std::endl;
        return false;
    }


    ssOut << "------------------------------ Crash Location ------------------------------" << std::endl;

    std::stringstream ssTemp;
    size_t iInstAdrs = iStartAdrs;
    bool bPasssedCrashLoc = false; // Did we pass by the instruction that caused signal?

    for(size_t iInstIndex = 0; iInstIndex < vecDecodedInst.size(); iInstIndex++)
    {
        if(iInstAdrs == pCrashLocation)
            bPasssedCrashLoc = true;

        ssTemp.clear();
        ssTemp.str("");

        InsaneDASM64::Instruction_t* pInst     = &vecDecodedInst[iInstIndex];
        InsaneDASM64::DASMInst_t*    pDasmInst = &vecDisassembledInst[iInstIndex];

        size_t iTotalBytes = 0;
        
        ssTemp << std::uppercase << std::hex << std::setfill('0');
        switch(pInst->m_iInstEncodingType)
        {
            case InsaneDASM64::Instruction_t::InstEncodingType_Legacy: 
                {
                    InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst = reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(pInst->m_pInst);
                    
                    // Legacy prefixies
                    iTotalBytes += pLegacyInst->m_legacyPrefix.m_nPrefix;
                    for(int iPrefixIndex = 0; iPrefixIndex < pLegacyInst->m_legacyPrefix.m_nPrefix; iPrefixIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_legacyPrefix.m_legacyPrefix[iPrefixIndex]);


                    // REX byte
                    if(pLegacyInst->m_bHasREX == true)
                    {
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_iREX);
                        iTotalBytes++;
                    }


                    // OpCodes
                    for(int iOpCodeIndex = 0; iOpCodeIndex < pLegacyInst->m_opCode.m_nOpBytes; iOpCodeIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_opCode.m_opBytes[iOpCodeIndex]);
                    iTotalBytes += pLegacyInst->m_opCode.m_nOpBytes;


                    // ModRm
                    if(pLegacyInst->m_bHasModRM == true)
                    {
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_modrm.Get());
                        iTotalBytes++;
                    }


                    // SIB
                    if(pLegacyInst->m_bHasSIB == true)
                    {
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_SIB.Get());
                        iTotalBytes++;
                    }


                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pLegacyInst->m_displacement.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_displacement.m_iDispBytes[iDispByteIndex]);
                    iTotalBytes += pLegacyInst->m_displacement.ByteCount();


                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pLegacyInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_immediate.m_immediateByte[iImmByteIndex]);
                    iTotalBytes += pLegacyInst->m_immediate.ByteCount();
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_VEX:
                {
                    InsaneDASM64::VEX::VEXInst_t* pVEXInst = reinterpret_cast<InsaneDASM64::VEX::VEXInst_t*>(pInst->m_pInst);

                    // VEX prefix
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iPrefix);
                    iTotalBytes++;

                    
                    // VEX bytes
                    for(int iVEXByteIndex = 0; iVEXByteIndex < pVEXInst->m_vexPrefix.m_nVEXBytes; iVEXByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iVEX[iVEXByteIndex]);
                    iTotalBytes += pVEXInst->m_vexPrefix.m_nVEXBytes;


                    // OpCode byte.
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_opcode.GetMostSignificantOpCode());
                    iTotalBytes++;


                    // ModRM
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_modrm.Get());
                    iTotalBytes++;


                    // SIB
                    if(pVEXInst->m_bHasSIB == true)
                    {
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_SIB.Get());
                        iTotalBytes++;
                    }


                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_disp.m_iDispBytes[iDispByteIndex]);
                    iTotalBytes += pVEXInst->m_disp.ByteCount();


                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_immediate.m_immediateByte[iImmByteIndex]);
                    iTotalBytes += pVEXInst->m_immediate.ByteCount();
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_EVEX:
                {
                    InsaneDASM64::EVEX::EVEXInst_t* pEVEXInst = reinterpret_cast<InsaneDASM64::EVEX::EVEXInst_t*>(pInst->m_pInst);

                    // EVEX prefix
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPrefix);
                    iTotalBytes++;


                    // EVEX payload
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload1);
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload2);
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload3);
                    iTotalBytes += 3;


                    // OpCode byte.
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_opcode.GetMostSignificantOpCode());
                    iTotalBytes++;


                    // ModRM
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_modrm.Get());
                    iTotalBytes++;


                    // SIB
                    if(pEVEXInst->m_bHasSIB == true)
                    {
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_SIB.Get());
                        iTotalBytes++;
                    }


                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pEVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_disp.m_iDispBytes[iDispByteIndex]);
                    iTotalBytes += pEVEXInst->m_disp.ByteCount();


                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pEVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_immediate.m_immediateByte[iImmByteIndex]);
                    iTotalBytes += pEVEXInst->m_immediate.ByteCount();
                }
                break;

            default: break;
        }
        ssTemp << std::nouppercase << std::dec << std::setfill(' ');
        ssOut << "0x" << std::hex << iInstAdrs << std::dec << "    " << std::left << std::setw(32) << ssTemp.str();

        iInstAdrs += iTotalBytes;


        switch(pDasmInst->m_nOperands)
        {
            case 0: ssOut << std::setw(10) << pDasmInst->m_szMnemonic; break;
            case 1: ssOut << std::setw(10) << pDasmInst->m_szMnemonic << ' ' << pDasmInst->m_szOperands[0]; break; 
            case 2: ssOut << std::setw(10) << pDasmInst->m_szMnemonic << ' ' << pDasmInst->m_szOperands[0] << ", " << pDasmInst->m_szOperands[1]; break;
            case 3: ssOut << std::setw(10) << pDasmInst->m_szMnemonic << ' ' << pDasmInst->m_szOperands[0] << ", " << pDasmInst->m_szOperands[1]
                    << ", " << pDasmInst->m_szOperands[2]; break;
            case 4: ssOut << std::setw(10) << pDasmInst->m_szMnemonic << ' ' << pDasmInst->m_szOperands[0] << ", " << pDasmInst->m_szOperands[1]
                    << ", " << pDasmInst->m_szOperands[2] << ", " << pDasmInst->m_szOperands[3]; break;

            default: break;
        }

        // if at crash inst. address, mark it.
        if(iInstAdrs - iTotalBytes == pCrashLocation)
            ssOut << "  <--[ crashed here ]";


        // Finding potential string pointer in this instruction.
        const char* szPotentialString = FindInstPointerToString(*pInst, iInstAdrs - iTotalBytes);
        if(szPotentialString != nullptr)
        {
            ssOut << " ; ";

            // Checking if we can read 20 bytes of this potential string.
            int iCharsToRead = DeadStop_t::GetInstance().GetStringDumpSize();

            uintptr_t iPotentialStringAdrs = reinterpret_cast<uintptr_t>(szPotentialString);
            if(g_memRegionHandler.HasParentRegion(iPotentialStringAdrs, iPotentialStringAdrs + iCharsToRead) == true)
            {
                for(int i = 0; i < iCharsToRead && szPotentialString[i] != '\0'; i++)
                {
                    ssOut << szPotentialString[i];
                }
            }
        }


        ssOut << '\n';
    }

    ssOut << '\n' << "----------------------------------------------------------------------------" << std::endl;


    // Deallocate all arenas...
    allocator.FreeAll();

    // Return whehter this disassembly was valid or not.
    return bPasssedCrashLoc;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static const char* DeadStop::FindInstPointerToString(InsaneDASM64::Instruction_t& inst, uintptr_t iStartAdrs)
{
    // In this function we will try to extract any poitners for some specific decoded instructions, 
    // and check if they point to some valid string in our processes memory region.
    //
    // Only LEA and legacy instructions with an 8 byte immediate, will be considered as potentially
    // "usefull".
    //
    // Fail output is nullptr, valid output is pointer to the string ( check against processes boundaries ).
    if(inst.m_iInstEncodingType != InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
        return nullptr;


    InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst = reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(inst.m_pInst);
    int iInstLengthInBytes = 0; // instruction length in bytes.
    {
        iInstLengthInBytes += pLegacyInst->m_legacyPrefix.m_nPrefix;
        iInstLengthInBytes += pLegacyInst->m_bHasREX == true ? 1 : 0;
        iInstLengthInBytes += pLegacyInst->m_opCode.m_nOpBytes;
        iInstLengthInBytes += pLegacyInst->m_bHasModRM == true ? 1 : 0;
        iInstLengthInBytes += pLegacyInst->m_bHasSIB == true ? 1 : 0;
        iInstLengthInBytes += pLegacyInst->m_displacement.ByteCount();
        iInstLengthInBytes += pLegacyInst->m_immediate.ByteCount();
    }

    if(pLegacyInst->m_opCode.m_pOpCodeDesc == nullptr)
        return nullptr;


    // To get the REG enum value corrosponding to modrm_rm or modrm_reg anything intel.
    static int s_regIndexToEnum[] = { REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RBP, REG_RSI, REG_RDI, 
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15 };


    // We will check this location for a valid string after filling it up.
    const char* szFinalPointer = nullptr;


    // We have a LEA instruction.
    if(strcmp(pLegacyInst->m_opCode.m_pOpCodeDesc->m_szName, "LEA") == 0)
    {
        if(pLegacyInst->ModRM_RM() != 0b100)
        {

            // Get the displacement value if there are any displacement bytes.
            // NOTE : Doing it this way assures that endians are handled correctly.
            int32_t iDisplacement = *reinterpret_cast<int32_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0]);
            switch(pLegacyInst->m_displacement.ByteCount())
            {
                // Single byte displacement. No need to worry about endians.
                case 1: iDisplacement &= 0xFF; break;
                case 2: iDisplacement &= 0xFFFF; break;
                case 4: iDisplacement &= 0xFFFFFFFF; break;

                default: iDisplacement = 0; break;
            }


            intptr_t iBaseReg =
                static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pLegacyInst->ModRM_RM()]]);


            // Incase of mod == 00 & rm = 101, we need to do : disp32 + RIP
            if(pLegacyInst->ModRM_Mod() == 0b00 && pLegacyInst->ModRM_RM() == 0b101)
            {
                iBaseReg = static_cast<intptr_t>(iStartAdrs) + static_cast<intptr_t>(iInstLengthInBytes);
            }
            else if(pLegacyInst->ModRM_Mod() != 0b11)
            {
                // Register holds to BS memory adrs?
                if(g_memRegionHandler.HasParentRegion(iBaseReg) == false)
                    return nullptr;

                iBaseReg = *reinterpret_cast<intptr_t*>(iBaseReg);
            }


            // Base register is pointing at valid memory address or not?
            if(g_memRegionHandler.HasParentRegion(iBaseReg) == false)
                return nullptr;


            // Final adrs...
            szFinalPointer = reinterpret_cast<const char*>(iBaseReg + iDisplacement);

            WIN_LOG("Found a potential string pointer [ %p ]", szFinalPointer);
        }
        else
        {
            intptr_t iBaseReg  = 
                static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pLegacyInst->SIB_Scale()]]);
            intptr_t iScaleReg =
                static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pLegacyInst->SIB_Index()]]);


            // Get the displacement value if there are any displacement bytes.
            // NOTE : Doing it this way assures that endians are handled correctly.
            int32_t iDisplacement = *reinterpret_cast<int32_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0]);
            switch(pLegacyInst->m_displacement.ByteCount())
            {
                // Single byte displacement. No need to worry about endians.
                case 1: iDisplacement &= 0xFF; break;
                case 2: iDisplacement &= 0xFFFF; break;
                case 4: iDisplacement &= 0xFFFFFFFF; break;

                default: iDisplacement = 0; break;
            }


            // Scale register...
            if(pLegacyInst->SIB_Index() == 0b100)
                iScaleReg = 0;


            // Base register...
            if(pLegacyInst->SIB_Base() == 0b101)
            {
                iBaseReg = 0;

                if(pLegacyInst->ModRM_Mod() == 0b01)
                {
                    iBaseReg       = static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[REG_RBP]);
                    iDisplacement &= 0xFF;
                }
                else if(pLegacyInst->ModRM_Mod() == 0b10)
                {
                    iBaseReg = static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[REG_RBP]);
                }
            }

            static int s_iScaleRegMult[4] = {1, 2, 4, 8};
            iScaleReg *= static_cast<intptr_t>(s_iScaleRegMult[pLegacyInst->SIB_Scale()]);

            szFinalPointer = reinterpret_cast<const char*>(iBaseReg + iScaleReg + iDisplacement);

            WIN_LOG("Found valid potential string pointer using SIB byte LEA. @ %p", szFinalPointer);
        }
    }


    // Final string lies in redable memory?
    if(g_memRegionHandler.HasParentRegion(reinterpret_cast<uintptr_t>(szFinalPointer)) == false)
        return nullptr;


    return szFinalPointer;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::Analyze()
{
    uintptr_t pCrashLoc = static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RIP]);

    std::vector<uintptr_t> vecCallStack; vecCallStack.push_back(pCrashLoc);

    for(int i = 0; i < 2; i++)
    {
        uintptr_t iReturnAdrs = GetReturnAdrs(vecCallStack.back());
        LOG("Return address detected : %p", iReturnAdrs);

        if(iReturnAdrs == 0)
            break;

        vecCallStack.push_back(iReturnAdrs);
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static uintptr_t DeadStop::GetReturnAdrs(uintptr_t iStartPos)
{
    if(DeadStop_t::GetInstance().IsInitialized() == false)
        return 0;


    ArenaAllocator_t allocator(8 * 1024); // 8 KiB arenas.
    
    // Rolling buffer for valid instruction pointers.
    constexpr size_t MAX_ADRS_BUFFER = 10;
    std::deque<uintptr_t> qValidInstAdrs;
    qValidInstAdrs.push_back(iStartPos);


    constexpr size_t DASM_BATCH_SIZE = 200;
    std::vector<InsaneDASM64::Byte> vecBytes(DASM_BATCH_SIZE);
    std::vector<InsaneDASM64::Instruction_t> vecInst;


    uintptr_t iRetInstAdrs = 0;
    bool      bRetFound    = false;
    for(int i = 0; i < 100; i++)
    {
        uintptr_t iBatchStartAdrs = qValidInstAdrs.back();
        uintptr_t iBatchEndAdrs   = iBatchStartAdrs + DASM_BATCH_SIZE;

        // Check if batch lies in valid memory or not.
        if(g_memRegionHandler.HasParentRegion(iBatchStartAdrs, iBatchEndAdrs) == false)
            break;


        // Store bytes.
        vecBytes.clear();
        for(size_t iByteIndex = 0; iByteIndex < DASM_BATCH_SIZE; iByteIndex++)
        {
            vecBytes.push_back(*(reinterpret_cast<InsaneDASM64::Byte*>(iBatchStartAdrs) + iByteIndex));
        }
        assertion(vecBytes.size() == DASM_BATCH_SIZE && "FUCK U NIGGA");


        // Decoder using bytes.
        vecInst.clear();
        if(InsaneDASM64::Decode(vecBytes, vecInst, allocator) != InsaneDASM64::IDASMErrorCode_Success)
            break;


        // Find return statement.
        for(InsaneDASM64::Instruction_t& inst : vecInst)
        {
            int iInstLength = 0;
            switch (inst.m_iInstEncodingType) 
            {
                case InsaneDASM64::Instruction_t::InstEncodingType_Legacy:
                    iInstLength += reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(inst.m_pInst)->GetInstLengthInBytes();
                    break;
                case InsaneDASM64::Instruction_t::InstEncodingType_VEX:
                    iInstLength += reinterpret_cast<InsaneDASM64::VEX::VEXInst_t*>(inst.m_pInst)->GetInstLengthInBytes();
                    break;
                case InsaneDASM64::Instruction_t::InstEncodingType_EVEX:
                    iInstLength += reinterpret_cast<InsaneDASM64::EVEX::EVEXInst_t*>(inst.m_pInst)->GetInstLengthInBytes();
                    break;

                default: break;
            }
            

            qValidInstAdrs.push_back(qValidInstAdrs.back() + iInstLength);
            if(qValidInstAdrs.size() > MAX_ADRS_BUFFER)
                qValidInstAdrs.pop_front();


            if(inst.m_iInstEncodingType != InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
                continue;


            InsaneDASM64::Legacy::LegacyInst_t* pInst = reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(inst.m_pInst);
            if(pInst->m_opCode.m_pOpCodeDesc == nullptr)
            {
                FAIL_LOG("Decoder failed :( BS Decoder.");
                continue;
            }

            // RETN instuction.
            // if(pInst->m_opCode.m_pOpCodeDesc->m_iByte == 0xC3 && pInst->m_opCode.m_nOpBytes == 1)
            if(strcmp(pInst->m_opCode.m_pOpCodeDesc->m_szName, "RETN") == 0)
            {
                bRetFound = true;
                break;
            }
        }

        if(bRetFound == true)
            break;

        // no free. just mark em as free.
        allocator.ResetAllArena();
    }


    if(bRetFound == false)
        return 0;


    vecBytes.clear(); vecInst.clear();
    allocator.ResetAllArena();
    for(uintptr_t iBatchStart = qValidInstAdrs.front(); iBatchStart < qValidInstAdrs.back(); iBatchStart++)
        vecBytes.push_back(*reinterpret_cast<InsaneDASM64::Byte*>(iBatchStart));


    if(InsaneDASM64::Decode(vecBytes, vecInst, allocator) != InsaneDASM64::IDASMErrorCode_Success)
    {
        FAIL_LOG("Decoder failed after running over these bytes once. What kind of decoder is this?");
        return 0;
    }

    std::vector<InsaneDASM64::DASMInst_t> vecOutput;
    if(InsaneDASM64::Disassemble(vecInst, vecOutput) != InsaneDASM64::IDASMErrorCode_Success)
    {
        FAIL_LOG("Theortically this can't fail, but I'm afraid this stands no chance against you.");
        return 0;
    }

    // Verifying decoding results. Final instruction in the output must be RETN
    if(strcmp(vecOutput.back().m_szMnemonic, "RETN") != 0)
    {
        FAIL_LOG("Expected a RETN statement @ the end. But got \"%s\"", vecOutput.back().m_szMnemonic);

        // for(InsaneDASM64::DASMInst_t& inst : vecOutput)
        // {
        //     printf("%s", inst.m_szMnemonic);
        //     for(int i = 0; i < inst.m_nOperands; i++) printf("%s, ", inst.m_szOperands[i]);
        //     printf("\n");
        // }

        return 0;
    }


    for(InsaneDASM64::DASMInst_t& inst : vecOutput)
    {
        printf("%s", inst.m_szMnemonic);
        for(int i = 0; i < inst.m_nOperands; i++) printf("%s, ", inst.m_szOperands[i]);

        printf("\n");
    }


    // There are less than 2 instructions between start & RETN instruction.
    // i.e. Start pos is restoring stack frame or some shit.
    // We can't determine return adrs without atleast 2 instructions.
    if(vecInst.size() <= 2)
        return 0;

    // second last instruction, right above RETN instruction.
    InsaneDASM64::Instruction_t* pMagicInst = &vecInst[vecInst.size() - 2];

    // What the fuck are we even disassembling?
    if(pMagicInst->m_iInstEncodingType != InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
        return 0;

    // If this instrucion is "LEAVE" or "POP rbp", then stack frame is not omitted.
    InsaneDASM64::Legacy::LegacyInst_t* pSecondLastInst = 
        reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(pMagicInst->m_pInst);

    int  iInstLength = pSecondLastInst->GetInstLengthInBytes();
    bool bLeaveInst  = iInstLength == 1 && pSecondLastInst->m_opCode.GetMostSignificantOpCode() == 0xC9;
    bool bPopRBP     = iInstLength == 1 && pSecondLastInst->m_opCode.GetMostSignificantOpCode() == 0x5D;
    bool bStackFrameOmitted = bLeaveInst == false && bPopRBP == false;


    // TODO : Add safety check here.
    // TODO : Understand all return paths n shit.
    if(bStackFrameOmitted == false)
    {
        WIN_LOG("Stack Frame Found");
        return *reinterpret_cast<uintptr_t*>(static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RBP]) + 8);
    }


    return 0;
}

    
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::DumpGeneralRegisters(std::fstream& hFile)
{
    static const char*  s_szGRegNames[__NGREG] = {
        "REG_R8", "REG_R9", "REG_R10", "REG_R11", "REG_R12", "REG_R13", "REG_R14", "REG_R15",
        "REG_RDI", "REG_RSI", "REG_RBP", "REG_RBX", "REG_RDX", "REG_RAX", "REG_RCX", "REG_RSP", "REG_RIP",
        "REG_EFL", "REG_CSGSFS", "REG_ERR", "REG_TRAPNO", "REG_OLDMASK", "REG_CR2"
    };


    // Longest register name ( used for formatting )
    size_t iMaxRegNameSize = 0; 
    for(int iRegIndex = 0; iRegIndex < __NGREG; iRegIndex++) 
        if(size_t iLen = strlen(s_szGRegNames[iRegIndex]); iLen > iMaxRegNameSize) 
            iMaxRegNameSize = iLen;


    hFile << std::uppercase << std::hex << std::setfill('0');

    hFile << "------------------------------ General Registers------------------------------" << std::endl;
    for(int iRegIndex = 0; iRegIndex < __NGREG; iRegIndex++)
    {
        // This register name's size.
        size_t iRegNameSize = strlen(s_szGRegNames[iRegIndex]);

        hFile << s_szGRegNames[iRegIndex];
        for(int i = 0; i < iMaxRegNameSize - iRegNameSize; i++) hFile << ' ';
        hFile << " : " << 
            std::setfill('0') << std::setw(16) << g_pContext->uc_mcontext.gregs[iRegIndex];

        if(g_pContext->uc_mcontext.gregs[iRegIndex] == 0)
            hFile << " [ zero ]";

        hFile << std::endl;
    }
    hFile << "------------------------------------------------------------------------------" << std::endl;

    hFile << std::nouppercase << std::dec << std::setfill(' ');
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::DumpDateTime(std::fstream& hFile)
{
    std::time_t now       = std::time(nullptr);
    std::tm*    localTime = std::localtime(&now);


    // Writing date.
    hFile << "Date { " << localTime->tm_mday << " ";
    switch(localTime->tm_mon)
    {
        case 0:  hFile << "January";   break;
        case 1:  hFile << "Febuary";   break;
        case 2:  hFile << "March";     break;
        case 3:  hFile << "April";     break;
        case 4:  hFile << "May";       break;
        case 5:  hFile << "June";      break;
        case 6:  hFile << "July";      break;
        case 7:  hFile << "August";    break;
        case 8:  hFile << "September"; break;
        case 9:  hFile << "October";   break;
        case 10: hFile << "November";  break;
        case 11: hFile << "December";  break;

        default: hFile << "Bitch-Ass-Month"; break;
    }
    hFile << " " << (localTime->tm_year + 1900) << " }";


    // Writting time.
    hFile << " Time { " 
        << localTime->tm_hour % 12 << ':' 
        << std::setw(2) << std::setfill('0') <<localTime->tm_min << ':' 
        << std::setw(2) << std::setfill('0') <<localTime->tm_sec << " "
        << (localTime->tm_hour >= 12 ? "PM" : "AM")
        << " }" << std::setfill(' ');
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::DoBranding(std::fstream& hFile)
{
    hFile << " [ DeadStop ]";
}
