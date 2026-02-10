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


    // Table to get ModRM.RM or ModRM.Reg to ucontext_t register index.
    static int s_regIndexToEnum[] = { REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RBP, REG_RSI, REG_RDI, 
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15 };


    // Generate formatted assembly instructions around a memory address.
    static bool DumpAssembly(std::fstream& hFile, uintptr_t pPivotLocation, int iAsmDumpRangeInBytes, const char* szRipMsg = nullptr);
    static bool GenerateDasmOutput( // This is a internal function used by DumpAssembly ( above ).
            std::stringstream& ssOut, uintptr_t iStartAdrs, const std::vector<InsaneDASM64::Byte>& vecBytes, uintptr_t pCrashLocation, const char* szRipMsg);
    static bool MakeSignature(
            std::stringstream& sigOut, const std::vector<InsaneDASM64::Instruction_t>& vecInst, size_t iStartIndex, size_t iSignatureSizeInBytes);

    static void* GetPointerFromModrm(InsaneDASM64::Instruction_t& inst, uintptr_t iStartAdrs);
    static void* GetPointerFromModrm(InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst, uintptr_t iStartAdrs);

    // Call stack analysis.
    static bool Analyze(std::vector<uintptr_t>& vecCallStack);
    static bool WriteFnChainToFile(std::fstream& hFile, const std::vector<uintptr_t>& vecCallStack);
    static uintptr_t GetReturnAdrs(uintptr_t iStartPos, ArenaAllocator_t& allocator);

    // String Utility.
    static bool CaseInsensitiveStringMatch(const char* szString1, const char* szString2);
    static bool IsCharPrintable(char c);

    // Write to File.
    static void WriteSelfMaps       (std::fstream& hFile);
    static void DumpGeneralRegisters(std::fstream& hFile);
    static void DumpDateTime        (std::fstream& hFile);
    static void DoBranding          (std::fstream& hFile);
    static void StartBanner         (std::fstream& hFile, const char* szMsg);
    static void EndBanner           (std::fstream& hFile, const char* szMsg);
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


    // Write the signal ID.
    switch(iSignalID)
    {
        case SIGSEGV:  DoBranding(hFile); hFile << "Signal received [ SIGSEGV ] i.e. Segfault\n";                        break;
        case SIGILL:   DoBranding(hFile); hFile << "Signal received [ SIGILL ] i.e. Invalid Instruction\n";              break;
        case SIGTRAP:  DoBranding(hFile); hFile << "Signal Received [ SIGTRAP ] i.e. Trap Debugger\n";                   break;
        case SIGABRT:  DoBranding(hFile); hFile << "Signal Received [ SIGABRT ] i.e. abort()\n";                         break; 
        case SIGFPE:   DoBranding(hFile); hFile << "Signal Received [ SIGFPE ] i.e. Devide By Zero\n";                   break;  
        case SIGBUS:   DoBranding(hFile); hFile << "Signal Received [ SIGBUS ] i.e. Hardware memory error, bad mmap.\n"; break; 

        default: assertion(false && "Invalid signal ID"); return;
    }
    hFile << "\n\n";
    /* Prologue ends here */


    g_pContext = reinterpret_cast<ucontext_t*>(pContext);
    g_pSigInfo = pSigInfo;


    // Getting "this" process's memory regions.
    std::vector<MemRegion_t> vecSelfMaps; 
    if(g_memRegionHandler.InitializeFromFile("/proc/self/maps") == false)
    {
        DoBranding(hFile); hFile << "Failed to open \"/proc/self/maps\". Cannot proceed any further.\n";
        return;
    }
    WriteSelfMaps(hFile);
    WIN_LOG("Got processes memory regions.");
    hFile << "\n\n";


    // GPR values -> file.
    DumpGeneralRegisters(hFile);
    WIN_LOG("Dumped registers.");
    hFile << "\n\n";


    std::vector<uintptr_t> vecCallStack;
    Analyze(vecCallStack);

    WriteFnChainToFile(hFile, vecCallStack);


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

    StartBanner(hFile, "Mapped Memory Regions");

    std::string szLine;
    while(std::getline(hMaps, szLine))
    {
        hFile << szLine << std::endl;
    }

    EndBanner(hFile, "Mapped Memory Regions");

    hMaps.close();
    return;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::DumpAssembly(std::fstream& hFile, uintptr_t pPivotLocation, int iAsmDumpRangeInBytes, const char* szRipMsg)
{
    // Does the crash location belong to the process?
    if(g_memRegionHandler.HasParentRegion(pPivotLocation) == false)
    {
        FAIL_LOG("Crash location [ %p ] is not a redable memory location. Cannot dump crash logs.", pPivotLocation);
        return false;
    }


    assertion(pPivotLocation > iAsmDumpRangeInBytes && "Invalid dump range or crash location?");
    assertion(iAsmDumpRangeInBytes > 0 && iAsmDumpRangeInBytes < 0x1000 && "invalid or Too big dump range");
    uintptr_t iAsmDumpStart = pPivotLocation - iAsmDumpRangeInBytes;
    uintptr_t iAsmDumpEnd   = pPivotLocation + iAsmDumpRangeInBytes;
    if(g_memRegionHandler.HasParentRegion(iAsmDumpStart, iAsmDumpEnd) == false)
    {
        hFile << "Some parts of the dump regions [ " << 
            std::hex << iAsmDumpStart << " - " << iAsmDumpEnd << 
            " ] can't be read, reducing dump region to 100 byte above & below\n";


        if(iAsmDumpRangeInBytes > 100)
        {
            iAsmDumpRangeInBytes = 100;
            iAsmDumpStart        = pPivotLocation - iAsmDumpRangeInBytes; 
            iAsmDumpEnd          = pPivotLocation + iAsmDumpRangeInBytes;
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
    for(int i = -iAsmDumpRange; i < iAsmDumpRange; i++) // unary minus ( - ) operator.
        vecBytes.push_back(*(reinterpret_cast<InsaneDASM64::Byte*>(pPivotLocation) + i));


    constexpr size_t  MAX_DISASSEMBLING_ATTEMPS = 10;
    std::stringstream ssDasmOutput;
    bool              bDasmSucceded = false;
    for(int iAttempt = 0; iAttempt < MAX_DISASSEMBLING_ATTEMPS; iAttempt++)
    {
        // Address of the first instruction.
        uintptr_t iStartAdrs = static_cast<uintptr_t>(
            static_cast<intptr_t>(pPivotLocation) - static_cast<intptr_t>(iAsmDumpRange) + static_cast<intptr_t>(iAttempt));


        ssDasmOutput.clear(); ssDasmOutput.str("");
        if(GenerateDasmOutput(ssDasmOutput, iStartAdrs, vecBytes, pPivotLocation, szRipMsg) == true)
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
        DoBranding(hFile); hFile << "Disassembly Failed.\n";
        return false;
    }


    hFile << ssDasmOutput.str();
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::GenerateDasmOutput(
        std::stringstream& ssOut, uintptr_t iStartAdrs, const std::vector<InsaneDASM64::Byte>& vecBytes, uintptr_t pCrashLocation, const char* szRipMsg)
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
        ssOut << "Where did you get this dog crap disassembler from?" << std::endl;
        return false;
    }


    std::stringstream ssTemp;
    size_t            iInstAdrs        = iStartAdrs;
    bool              bPasssedCrashLoc = false; // Did we pass by the instruction that caused signal?

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

                    iTotalBytes += pLegacyInst->GetInstLengthInBytes();
                    
                    // Legacy prefixies
                    for(int iPrefixIndex = 0; iPrefixIndex < pLegacyInst->m_legacyPrefix.m_nPrefix; iPrefixIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_legacyPrefix.m_legacyPrefix[iPrefixIndex]);

                    // REX byte
                    if(pLegacyInst->m_bHasREX == true)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_iREX);

                    // OpCodes
                    for(int iOpCodeIndex = 0; iOpCodeIndex < pLegacyInst->m_opCode.m_nOpBytes; iOpCodeIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_opCode.m_opBytes[iOpCodeIndex]);

                    // ModRm
                    if(pLegacyInst->m_bHasModRM == true)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_modrm.Get());

                    // SIB
                    if(pLegacyInst->m_bHasSIB == true)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_SIB.Get());

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pLegacyInst->m_displacement.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_displacement.m_iDispBytes[iDispByteIndex]);

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pLegacyInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pLegacyInst->m_immediate.m_immediateByte[iImmByteIndex]);
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_VEX:
                {
                    InsaneDASM64::VEX::VEXInst_t* pVEXInst = reinterpret_cast<InsaneDASM64::VEX::VEXInst_t*>(pInst->m_pInst);

                    iTotalBytes += pVEXInst->GetInstLengthInBytes();

                    // VEX prefix
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iPrefix);
                    
                    // VEX bytes
                    for(int iVEXByteIndex = 0; iVEXByteIndex < pVEXInst->m_vexPrefix.m_nVEXBytes; iVEXByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iVEX[iVEXByteIndex]);

                    // OpCode byte.
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_opcode.GetMostSignificantOpCode());

                    // ModRM
                    ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_modrm.Get());

                    // SIB
                    if(pVEXInst->m_bHasSIB == true)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_SIB.Get());

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_disp.m_iDispBytes[iDispByteIndex]);

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pVEXInst->m_immediate.m_immediateByte[iImmByteIndex]);
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_EVEX:
                {
                    InsaneDASM64::EVEX::EVEXInst_t* pEVEXInst = reinterpret_cast<InsaneDASM64::EVEX::EVEXInst_t*>(pInst->m_pInst);

                    iTotalBytes += pEVEXInst->GetInstLengthInBytes();

                    // EVEX prefix
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPrefix);

                    // EVEX payload
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload1);
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload2);
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload3);

                    // OpCode byte.
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_opcode.GetMostSignificantOpCode());

                    // ModRM
                    ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_modrm.Get());

                    // SIB
                    if(pEVEXInst->m_bHasSIB == true)
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_SIB.Get());

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pEVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_disp.m_iDispBytes[iDispByteIndex]);

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pEVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        ssTemp << std::setw(2) << static_cast<int>(pEVEXInst->m_immediate.m_immediateByte[iImmByteIndex]);
                }
                break;

            default: break;
        }
        ssTemp << std::nouppercase << std::dec << std::setfill(' ');
        ssOut << "0x" << std::hex << iInstAdrs << std::dec << "    " << std::left << std::setw(32) << ssTemp.str();


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
        if(iInstAdrs == pCrashLocation)
        {
            ssOut << "  <--[ " << szRipMsg << " ]";

            // Generating signature.
            int iSignatureSize = DeadStop_t::GetInstance().GetSignatureSize();
            if(iSignatureSize > 0)
            {
                ssOut << " Sig : ";
                MakeSignature(ssOut, vecDecodedInst, iInstIndex, DeadStop_t::GetInstance().GetSignatureSize());
            }
        }


        // Finding potential string pointer in this instruction.
        const char* szPotentialString = reinterpret_cast<const char*>(GetPointerFromModrm(*pInst, iInstAdrs));

        if(szPotentialString != nullptr)
        {
            ssOut << " ; ";

            // Checking if we can read 20 bytes of this potential string.
            int iCharsToRead = DeadStop_t::GetInstance().GetStringDumpSize();

            uintptr_t iPotentialStringAdrs = reinterpret_cast<uintptr_t>(szPotentialString);
            if(g_memRegionHandler.HasParentRegion(iPotentialStringAdrs, iPotentialStringAdrs + iCharsToRead) == true)
            {
                for(int i = 0; i < iCharsToRead; i++)
                {
                    if(szPotentialString[i] == '\0')
                        break;

                    if(IsCharPrintable(szPotentialString[i]) == false)
                        break;

                    ssOut << szPotentialString[i];
                }
            }
        }

        iInstAdrs += iTotalBytes;

        ssOut << '\n';
    }


    // Deallocate all arenas...
    allocator.FreeAll();

    // Return whehter this disassembly was valid or not.
    return bPasssedCrashLoc;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::MakeSignature(
        std::stringstream& sigOut, const std::vector<InsaneDASM64::Instruction_t>& vecInst, size_t iStartIndex, size_t iSignatureSizeInBytes)
{
    if(vecInst.empty() == true)
        return false;


    sigOut << std::uppercase << std::hex << std::setfill('0');

    int nInstCount = vecInst.size();
    int iSigSize   = 0;
    for(int iInstIndex = iStartIndex; iInstIndex < nInstCount; iInstIndex++)
    {
        const InsaneDASM64::Instruction_t* pInst = &vecInst[iInstIndex];


        if(static_cast<size_t>(iSigSize) >= iSignatureSizeInBytes)
            break;


        switch(pInst->m_iInstEncodingType)
        {
            case InsaneDASM64::Instruction_t::InstEncodingType_Legacy: 
                {
                    InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst = reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(pInst->m_pInst);
                    iSigSize += pLegacyInst->GetInstLengthInBytes();

                    // Legacy prefixies
                    for(int iPrefixIndex = 0; iPrefixIndex < pLegacyInst->m_legacyPrefix.m_nPrefix; iPrefixIndex++)
                        sigOut << std::setw(2) << static_cast<int>(pLegacyInst->m_legacyPrefix.m_legacyPrefix[iPrefixIndex]) << ' ';

                    // REX byte
                    if(pLegacyInst->m_bHasREX == true)
                        sigOut << std::setw(2) << static_cast<int>(pLegacyInst->m_iREX) << ' ';

                    // OpCodes
                    for(int iOpCodeIndex = 0; iOpCodeIndex < pLegacyInst->m_opCode.m_nOpBytes; iOpCodeIndex++)
                        sigOut << std::setw(2) << static_cast<int>(pLegacyInst->m_opCode.m_opBytes[iOpCodeIndex]) << ' ';

                    // ModRm
                    if(pLegacyInst->m_bHasModRM == true)
                        sigOut << std::setw(2) << static_cast<int>(pLegacyInst->m_modrm.Get()) << ' ';

                    // SIB
                    if(pLegacyInst->m_bHasSIB == true)
                        sigOut << std::setw(2) << static_cast<int>(pLegacyInst->m_SIB.Get()) << ' ';

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pLegacyInst->m_displacement.ByteCount(); iDispByteIndex++)
                        sigOut << "? ";

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pLegacyInst->m_immediate.ByteCount(); iImmByteIndex++)
                        sigOut << "? ";
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_VEX:
                {
                    InsaneDASM64::VEX::VEXInst_t* pVEXInst = reinterpret_cast<InsaneDASM64::VEX::VEXInst_t*>(pInst->m_pInst);
                    iSigSize += pVEXInst->GetInstLengthInBytes();

                    // VEX prefix
                    sigOut << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iPrefix) << ' ';
                    
                    // VEX bytes
                    for(int iVEXByteIndex = 0; iVEXByteIndex < pVEXInst->m_vexPrefix.m_nVEXBytes; iVEXByteIndex++)
                        sigOut << std::setw(2) << static_cast<int>(pVEXInst->m_vexPrefix.m_iVEX[iVEXByteIndex]) << ' ';

                    // OpCode byte.
                    sigOut << std::setw(2) << static_cast<int>(pVEXInst->m_opcode.GetMostSignificantOpCode()) << ' ';

                    // ModRM
                    sigOut << std::setw(2) << static_cast<int>(pVEXInst->m_modrm.Get()) << ' ';

                    // SIB
                    if(pVEXInst->m_bHasSIB == true)
                        sigOut << std::setw(2) << static_cast<int>(pVEXInst->m_SIB.Get()) << ' ';

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        sigOut << "? ";

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        sigOut << "? ";
                }
                break;

            case InsaneDASM64::Instruction_t::InstEncodingType_EVEX:
                {
                    InsaneDASM64::EVEX::EVEXInst_t* pEVEXInst = reinterpret_cast<InsaneDASM64::EVEX::EVEXInst_t*>(pInst->m_pInst);
                    iSigSize = pEVEXInst->GetInstLengthInBytes();

                    // EVEX prefix
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPrefix) << ' ';

                    // EVEX payload
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload1) << ' ';
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload2) << ' ';
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_evexPrefix.m_iPayload3) << ' ';

                    // OpCode byte.
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_opcode.GetMostSignificantOpCode()) << ' ';

                    // ModRM
                    sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_modrm.Get()) << ' ';

                    // SIB
                    if(pEVEXInst->m_bHasSIB == true)
                        sigOut << std::setw(2) << static_cast<int>(pEVEXInst->m_SIB.Get()) << ' ';

                    // Displacement
                    for(int iDispByteIndex = 0; iDispByteIndex < pEVEXInst->m_disp.ByteCount(); iDispByteIndex++)
                        sigOut << "? ";

                    // Immediate
                    for(int iImmByteIndex = 0; iImmByteIndex < pEVEXInst->m_immediate.ByteCount(); iImmByteIndex++)
                        sigOut << "? ";
                }
                break;

            default: break;
        }
    }

    sigOut << std::nouppercase << std::dec << std::setfill(' ');


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void* DeadStop::GetPointerFromModrm(InsaneDASM64::Instruction_t& inst, uintptr_t iStartAdrs)
{
    if(inst.m_iInstEncodingType != InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
        return nullptr;

    return GetPointerFromModrm(reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(inst.m_pInst), iStartAdrs);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void* DeadStop::GetPointerFromModrm(InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst, uintptr_t iStartAdrs)
{
    int iInstLengthInBytes = pLegacyInst->GetInstLengthInBytes(); // instruction length in bytes.

    if(pLegacyInst->m_opCode.m_pOpCodeDesc == nullptr)
        return nullptr;

    if(pLegacyInst->m_bHasModRM == false)
        return nullptr;


    // We will check this location for a valid string after filling it up.
    void* szFinalPointer = nullptr;


    // We have a LEA instruction.
    if(pLegacyInst->ModRM_RM() != 0b100)
    {

        // Get the displacement value if there are any displacement bytes.
        int32_t iDisplacement = 0;
        switch(pLegacyInst->m_displacement.ByteCount())
        {
            // NOTE : Doing it this way handles endian & sign / zero extension.
            case 1: iDisplacement = static_cast<int32_t>(static_cast<int8_t>(pLegacyInst->m_displacement.m_iDispBytes[0])); break;
            case 2: iDisplacement = static_cast<int32_t>(*reinterpret_cast<int16_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0])); break;
            case 4: iDisplacement = *reinterpret_cast<int32_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0]); break;

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
        szFinalPointer = reinterpret_cast<void*>(iBaseReg + iDisplacement);

        WIN_LOG("Found a potential string pointer [ %p ]", szFinalPointer);
    }
    else if(pLegacyInst->m_bHasSIB == true)
    {
        intptr_t iBaseReg  = 
            static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pLegacyInst->SIB_Scale()]]);
        intptr_t iScaleReg =
            static_cast<intptr_t>(g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pLegacyInst->SIB_Index()]]);


        // Get the displacement value if there are any displacement bytes.
        int32_t iDisplacement = 0;
        switch(pLegacyInst->m_displacement.ByteCount())
        {
            // NOTE : Doing it this way handles endian & sign / zero extension.
            case 1: iDisplacement = static_cast<int32_t>(static_cast<int8_t>(pLegacyInst->m_displacement.m_iDispBytes[0])); break;
            case 2: iDisplacement = static_cast<int32_t>(*reinterpret_cast<int16_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0])); break;
            case 4: iDisplacement = *reinterpret_cast<int32_t*>(&pLegacyInst->m_displacement.m_iDispBytes[0]); break;

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

        szFinalPointer = reinterpret_cast<void*>(iBaseReg + iScaleReg + iDisplacement);
        if(g_memRegionHandler.HasParentRegion(reinterpret_cast<uintptr_t>(szFinalPointer)) == false)
            return nullptr;

        szFinalPointer = *reinterpret_cast<void**>(szFinalPointer);

        WIN_LOG("Found a potential string pointer [ %p ]", szFinalPointer);
    }
    else 
    {
        FAIL_LOG("Found instruction with a modrm.rm = 100 and not SIB byte.");
    }


    // Final string lies in redable memory?
    if(g_memRegionHandler.HasParentRegion(reinterpret_cast<uintptr_t>(szFinalPointer)) == false)
        return nullptr;


    return szFinalPointer;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::Analyze(std::vector<uintptr_t>& vecCallStack)
{
    uintptr_t pCrashLoc = static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RIP]);

    vecCallStack.clear(); vecCallStack.push_back(pCrashLoc);

    ArenaAllocator_t allocator(8 * 1024); // 8 KiB arenas.
                                          
    int iCallStackDepth = DeadStop_t::GetInstance().GetCallStackDepth();
    for(int i = 0; i < iCallStackDepth; i++)
    {
        allocator.ResetAllArena();

        uintptr_t iReturnAdrs = GetReturnAdrs(vecCallStack.back(), allocator);
        LOG("Return address detected : %p", iReturnAdrs);

        if(iReturnAdrs == 0)
            break;

        vecCallStack.push_back(iReturnAdrs);
    }

    allocator.FreeAll();

    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::WriteFnChainToFile(std::fstream& hFile, const std::vector<uintptr_t>& vecCallStack)
{
    if(vecCallStack.empty() == true)
        return false;


    DoBranding(hFile); hFile << "Call Stack : \n";
    for(size_t iFnIndex = 0; iFnIndex < vecCallStack.size(); iFnIndex++)
    {
        hFile << "    "; // Indentation.
        hFile << iFnIndex << ". ";
        hFile << std::uppercase << std::hex << "0x" << vecCallStack[iFnIndex] << std::nouppercase << std::dec;
        if(iFnIndex == 0)
            hFile << " <--[ crashed here ]";

        hFile << '\n';
    }
    hFile << '\n';


    std::stringstream ssTemp;
    int iAsmDumpRange = DeadStop_t::GetInstance().GetAsmDumpRange();
    for(size_t iFnIndex = 0; iFnIndex < vecCallStack.size(); iFnIndex++)
    {
        ssTemp.clear(); ssTemp.str("");
        ssTemp << "Function Index : " << iFnIndex << ". Adrs : 0x" << std::uppercase << std::hex << vecCallStack[iFnIndex] << std::nouppercase << std::dec;
        StartBanner(hFile, ssTemp.str().c_str());

        if(DumpAssembly(hFile, vecCallStack[iFnIndex], iAsmDumpRange, iFnIndex == 0 ? "Crashed Here" : "Return Adrs") == false)
            break;

        EndBanner(hFile, ssTemp.str().c_str());
        hFile << '\n';
    }

    
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static uintptr_t DeadStop::GetReturnAdrs(uintptr_t iStartPos, ArenaAllocator_t& allocator)
{
    if(DeadStop_t::GetInstance().IsInitialized() == false)
        return 0;

    
    // Rolling buffer for valid instruction pointers.
    constexpr size_t MAX_ADRS_BUFFER = 10;
    std::deque<uintptr_t> qValidInstAdrs;
    qValidInstAdrs.push_back(iStartPos);


    constexpr size_t DASM_BATCH_SIZE = 200;
    std::vector<InsaneDASM64::Byte> vecBytes(DASM_BATCH_SIZE);
    std::vector<InsaneDASM64::Instruction_t> vecInst;


    int64_t iPushPopOffset = 0; // How much have Push & Pop instuctions moved RSP in between StartPos to RETN inst.
    bool    bRetFound      = false;
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
        assertion(vecBytes.size() == DASM_BATCH_SIZE);
 

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
                    {
                        InsaneDASM64::Legacy::LegacyInst_t* pLegacyInst =
                            reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(inst.m_pInst);

                        if(InsaneDASM64::Standard::OpCodeDesc_t* pOpcdDesc = pLegacyInst->m_opCode.m_pOpCodeDesc; pOpcdDesc != nullptr)
                        {
                            if(CaseInsensitiveStringMatch(pOpcdDesc->m_szName, "PUSH") == true)
                                iPushPopOffset -= 8;
                            else if(CaseInsensitiveStringMatch(pOpcdDesc->m_szName, "POP") == true)
                                iPushPopOffset += 8;
                        }


                        iInstLength += pLegacyInst->GetInstLengthInBytes();
                    }
                    break;
                case InsaneDASM64::Instruction_t::InstEncodingType_VEX:
                    iInstLength += reinterpret_cast<InsaneDASM64::VEX::VEXInst_t*>(inst.m_pInst)->GetInstLengthInBytes();
                    break;
                case InsaneDASM64::Instruction_t::InstEncodingType_EVEX:
                    iInstLength += reinterpret_cast<InsaneDASM64::EVEX::EVEXInst_t*>(inst.m_pInst)->GetInstLengthInBytes();
                    break;

                    // Can happen for instructions whose full byte weren't feed.
                case InsaneDASM64::Instruction_t::InstEncodingType_Invalid:
                default: continue;
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

        // no free. just mark it as free.
        allocator.ResetAllArena();
    }


    if(bRetFound == false)
        return 0;


    LOG("A PushPop offset of [ %ld ] is determined", iPushPopOffset);


    // Store fresh bytes, till RETN inst.
    vecBytes.clear();
    vecInst.clear();
    allocator.ResetAllArena();
    for(uintptr_t iBatchStart = qValidInstAdrs.front(); iBatchStart < qValidInstAdrs.back(); iBatchStart++)
        vecBytes.push_back(*reinterpret_cast<InsaneDASM64::Byte*>(iBatchStart));


    if(InsaneDASM64::Decode(vecBytes, vecInst, allocator) != InsaneDASM64::IDASMErrorCode_Success)
    {
        FAIL_LOG("Decoder failed after running over these bytes once. What kind of decoder is this?");
        return 0;
    }

    std::vector<InsaneDASM64::DASMInst_t> vecDasmInst;
    if(InsaneDASM64::Disassemble(vecInst, vecDasmInst) != InsaneDASM64::IDASMErrorCode_Success)
    {
        FAIL_LOG("Theortically this can't fail, but I'm afraid this stands no chance against you.");
        return 0;
    }

    assertion(vecInst.size() == vecDasmInst.size() && "Decoded & Disasembled instruction count doens't match.");
    // qValidInstAdrs holds memory addresses of consecutive instrutions. when we disassemble from first
    // entry to last entry we get one less instruction than entries, because :
    // 0, 1, 2, 3, 4, 5         Total 6
    // 0-1, 1-2, 2-3, 3-4, 4-5, Total 5
    // i.e. no bytes for last instruction according in qValidInstAdrs.
    assertion(qValidInstAdrs.size() - 1 == vecDasmInst.size() && "Valid instruction addresses don't line up with disassembled inst count.");


    // Verifying decoding results. Final instruction in the output must be RETN
    if(strcmp(vecDasmInst.back().m_szMnemonic, "RETN") != 0)
    {
        FAIL_LOG("Expected a RETN statement @ the end. But got \"%s\"", vecDasmInst.back().m_szMnemonic);
        return 0;
    }


    // if less than 2 instructions between start adrs & RETN inst adrs.
    // then we caused "signal" in stack frame's epilogue. and thats BS.
    if(vecInst.size() <= 2)
        return 0;


    // second last instruction, right above RETN instruction.
    InsaneDASM64::Instruction_t* pMagicInst = &vecInst[vecInst.size() - 2];

    // Must only have Legacy encoded instructions in stack frame epilogue. 
    if(pMagicInst->m_iInstEncodingType != InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
        return 0;


    InsaneDASM64::Legacy::LegacyInst_t* pSecondLastInst = 
        reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(pMagicInst->m_pInst);

    // If this instrucion is "LEAVE" or "POP rbp", then stack frame is not omitted.
    int  iInstLength = pSecondLastInst->GetInstLengthInBytes();
    bool bLeaveInst  = iInstLength == 1 && pSecondLastInst->m_opCode.GetMostSignificantOpCode() == 0xC9; // "LEAVE" inst
    bool bPopRBP     = iInstLength == 1 && pSecondLastInst->m_opCode.GetMostSignificantOpCode() == 0x5D; // "POP rbp" inst
    bool bStackFrameOmitted = bLeaveInst == false && bPopRBP == false;


    if(bStackFrameOmitted == false)
    {
        WIN_LOG("This function has a stack frame.");

        // At rBP is the pushed rBP (from stack frame prologue.). Next to that is the return adrs.
        uintptr_t pReturnAdrs = static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RBP]) + 8;
        if(g_memRegionHandler.HasParentRegion(pReturnAdrs) == false)
            return 0;

        uintptr_t iReturnAdrs = *reinterpret_cast<uintptr_t*>(pReturnAdrs);
        if(g_memRegionHandler.HasParentRegion(iReturnAdrs) == false)
            return 0;

        return iReturnAdrs;
    }



    // Stack frame omitted.
    // Iterate from second last to front, and find the first instruction which
    // modifies the rSP register. Should be the second inst itself in most cases.
    InsaneDASM64::Legacy::LegacyInst_t* pStackRestoringInst     = nullptr;
    uintptr_t                           iAdrsStackRestoringInst = 0;
    for(int iInstIndex = static_cast<int>(vecInst.size()) - 2; iInstIndex >= 0; iInstIndex--)
    {
        InsaneDASM64::DASMInst_t*    pDasmInst = &vecDasmInst[iInstIndex];
        InsaneDASM64::Instruction_t* pInst     = &vecInst[iInstIndex];
        uintptr_t                    iInstAdrs = qValidInstAdrs[iInstIndex - 1]; // -1 cause @ last index is adrs of inst next to RETN.

        // Break @ first rSP modifying instruction.
        if(pInst->m_iInstEncodingType == InsaneDASM64::Instruction_t::InstEncodingType_Legacy)
        {
            if(pDasmInst->m_nOperands >= 1 && CaseInsensitiveStringMatch(pDasmInst->m_szOperands[0], "rsp") == true)
            {
                WIN_LOG("Found rsp modifying instruction. @ %p", iInstAdrs);
                LOG("%s %s, %s", pDasmInst->m_szMnemonic, pDasmInst->m_szOperands[0], pDasmInst->m_szOperands[1]);

                pStackRestoringInst     = reinterpret_cast<InsaneDASM64::Legacy::LegacyInst_t*>(pInst->m_pInst);
                iAdrsStackRestoringInst = iInstAdrs;
                break;
            }
        }
    }


    // This function failed both "Normal Stack Frame" & "Omitted Stack Check"
    // This function must be a leaf function, hence rsp is unchanged.
    if(pStackRestoringInst == nullptr)
    {
        // Push Pop can still occur in leaf fns?
        uintptr_t pReturnAdrs = static_cast<uintptr_t>(g_pContext->uc_mcontext.gregs[REG_RSP] + iPushPopOffset); 
        if(g_memRegionHandler.HasParentRegion(pReturnAdrs) == false)
            return 0;

        uintptr_t iReturnAdrs = *reinterpret_cast<uintptr_t*>(pReturnAdrs);
        if(g_memRegionHandler.HasParentRegion(iReturnAdrs) == false)
            return 0;

        return iReturnAdrs;
    }


    if(pStackRestoringInst->m_opCode.m_pOpCodeDesc == nullptr)
    {
        FAIL_LOG("OpCode description of a Stack restoring instruction for an omitted stack frame function is invalid.");
        return 0;
    }

    // If stack restoring inst is a "LEA" instruction.
    if(CaseInsensitiveStringMatch(pStackRestoringInst->m_opCode.m_pOpCodeDesc->m_szName, "LEA") == true)
    {
        // No Push Pop offset here, LEA will load the correct adrs at once.
        uintptr_t pReturnAdrs = reinterpret_cast<uintptr_t>(GetPointerFromModrm(pStackRestoringInst, iAdrsStackRestoringInst));
        if(g_memRegionHandler.HasParentRegion(pReturnAdrs) == false) // Failed to get return address. 
            return 0;

        uintptr_t iReturnAdrs = *reinterpret_cast<uintptr_t*>(pReturnAdrs);
        if(g_memRegionHandler.HasParentRegion(iReturnAdrs) == false) // We got something, but it seems to be invalid.
            return 0;

        return iReturnAdrs;
    }
    else if(CaseInsensitiveStringMatch(pSecondLastInst->m_opCode.m_pOpCodeDesc->m_szName, "ADD") == true)
    {
        // just for ease of writting.
        InsaneDASM64::Legacy::LegacyInst_t* pInst = pStackRestoringInst;

        if(pInst->m_opCode.m_pOpCodeDesc->m_nOperands != 2)
           return 0;

        InsaneDASM64::Standard::OpCodeDesc_t* pOpcdDesc = pInst->m_opCode.m_pOpCodeDesc;

        if(pOpcdDesc->m_operands[1].m_iOperandCatagory != InsaneDASM64::Standard::Operand_t::OperandCatagory_Legacy)
            return 0;


        // NOTE : I have checked and only these 3 types of operand addressing methods are 
        // available for "ADD" instruction's second operand.
        intptr_t iRSPOffset = 0;
        if(pOpcdDesc->m_operands[1].m_iOperandMode == InsaneDASM64::Standard::OperandMode_G)
        {
            if(pInst->m_bHasModRM == false)
                return 0;

            iRSPOffset = g_pContext->uc_mcontext.gregs[s_regIndexToEnum[pInst->ModRM_Reg()]];
        }
        else if(pOpcdDesc->m_operands[1].m_iOperandMode == InsaneDASM64::Standard::OperandMode_E)
        {
            iRSPOffset = reinterpret_cast<intptr_t>(GetPointerFromModrm(pInst, iAdrsStackRestoringInst));
        }
        else if(pOpcdDesc->m_operands[1].m_iOperandMode == InsaneDASM64::Standard::OperandMode_I)
        {
            // NOTE : Doing it this way, will handle sign/zero extension & endian.
            int64_t iImmediate = 0;
            switch(pInst->m_immediate.ByteCount())
            {
                case 1: iImmediate = static_cast<intptr_t>(static_cast<int8_t>(pInst->m_immediate.m_immediateByte[0])); break;
                case 2: iImmediate = static_cast<intptr_t>(*reinterpret_cast<int16_t*>(&pInst->m_immediate.m_immediateByte[0])); break;
                case 4: iImmediate = static_cast<intptr_t>(*reinterpret_cast<int32_t*>(&pInst->m_immediate.m_immediateByte[0])); break;
                case 8: iImmediate = *reinterpret_cast<intptr_t*>(&pInst->m_immediate.m_immediateByte[0]); break;

                default: iImmediate = 0; break;
            }

            iRSPOffset = iImmediate;
        }


        uintptr_t pReturnAdrs = g_pContext->uc_mcontext.gregs[REG_RSP] + iRSPOffset + iPushPopOffset;
        if(g_memRegionHandler.HasParentRegion(pReturnAdrs) == false) // Failed to get return address. 
            return 0;

        uintptr_t iReturnAdrs = *reinterpret_cast<uintptr_t*>(pReturnAdrs);
        if(g_memRegionHandler.HasParentRegion(iReturnAdrs) == false) // We got something, but it seems to be invalid.
            return 0;


        return iReturnAdrs;
    }


    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::CaseInsensitiveStringMatch(const char* szString1, const char* szString2)
{
    if(szString1 == szString2)
        return true;

    if(szString1 == nullptr ||szString2 == nullptr)
        return false;

    while(*szString1 != 0 && *szString2 != 0)
    {
        char c1 = *szString1++;
        char c2 = *szString2++;

        // lower case all
        if(c1 >= 'A' && c1 <= 'Z')
            c1 = c1 - 'A' + 'a';

        // lower case all
        if(c2 >= 'A' && c2 <= 'Z')
            c2 = c2 - 'A' + 'a';

        if(c1 != c2)
            return false;
    }

    return *szString1 == 0 && *szString2 == 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool DeadStop::IsCharPrintable(char c)
{
    return c >= 32 && c <= 126;
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


    StartBanner(hFile, "General Purpose Registers");

    hFile << std::uppercase << std::hex << std::setfill('0');
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
    hFile << std::nouppercase << std::dec << std::setfill(' ');

    EndBanner(hFile, "General Purpose Registers");
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
    hFile << " [ DeadStop ] ";
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::StartBanner(std::fstream& hFile, const char* szMsg)
{
    hFile << "[ Start ]------------------------------->  " << szMsg << std::endl;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::EndBanner(std::fstream& hFile, const char* szMsg)
{
    hFile << "[  End  ]------------------------------->  " << szMsg << std::endl;
}
