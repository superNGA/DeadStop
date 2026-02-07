//=========================================================================
//                      Signal Handler
//=========================================================================
// by      : INSANE
// created : 06/02/2026
//
// purpose : Handler roughly all common signals received from OS.
//-------------------------------------------------------------------------
#include "SignalHandler.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <fstream>
#include "../DeadStopImpl.h"

// Disassembler.
#include "../../lib/IDASM/Include/INSANE_DisassemblerAMD64.h"
#include <csignal>

// Utility
#include "../Util/Assertion/Assertion.h"
#include "../Util/Terminal/Terminal.h"


// Mind this...
using namespace DeadStop;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
namespace DEADSTOP_NAMESPACE
{
    static void SignalHandler_SIGILL (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);
    static void SignalHandler_SIGTRAP(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);
    static void SignalHandler_SIGABRT(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);
    static void SignalHandler_SIGFPE (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);
    static void SignalHandler_SIGBUS (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);
    static void SignalHandler_SIGSEGV(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext);


    // Write-to-file fns...
    static void DumpGeneralRegisters(std::fstream& hFile, ucontext_t* pContext);
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


    ucontext_t* pUContext = reinterpret_cast<ucontext_t*>(pContext);
    switch(iSignalID)
    {
        case SIGSEGV: SignalHandler_SIGSEGV(hFile, iSignalID, pSigInfo, pUContext); break;
        case SIGILL:  SignalHandler_SIGILL (hFile, iSignalID, pSigInfo, pUContext); break;
        case SIGTRAP: SignalHandler_SIGTRAP(hFile, iSignalID, pSigInfo, pUContext); break;
        case SIGABRT: SignalHandler_SIGABRT(hFile, iSignalID, pSigInfo, pUContext); break;
        case SIGFPE:  SignalHandler_SIGFPE (hFile, iSignalID, pSigInfo, pUContext); break;
        case SIGBUS:  SignalHandler_SIGBUS (hFile, iSignalID, pSigInfo, pUContext); break;

        default: assertion(false && "Invalid signal ID"); return;
    }


    hFile.close();
    abort();
}



static void DeadStop::SignalHandler_SIGILL (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext) {return;}
static void DeadStop::SignalHandler_SIGTRAP(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext) {return;}
static void DeadStop::SignalHandler_SIGABRT(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext) {return;}
static void DeadStop::SignalHandler_SIGFPE (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext) {return;}
static void DeadStop::SignalHandler_SIGBUS (std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext) {return;}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::SignalHandler_SIGSEGV(std::fstream& hFile, int iSignalID, siginfo_t* pSigInfo, ucontext_t* pContext)
{
    assertion(iSignalID == SIGSEGV && "Invalid signal received in SIGSEGV handler");

    hFile << "Signal received [ SIGSEGV ] i.e. segfault\n";


    // Dump all general purpose registers with their values.
    DumpGeneralRegisters(hFile, pContext);


    void* pCrashLocation = reinterpret_cast<void*>(pContext->uc_mcontext.gregs[REG_RIP]);


    // Collecting some bytes from crash location to disassembler.
    std::vector<InsaneDASM64::Byte> vecBytes;
    for(int i = -50; i < 50; i++)
        vecBytes.push_back(*(reinterpret_cast<InsaneDASM64::Byte*>(pCrashLocation) + i));


    // Decoder & Disassembler.
    std::vector<InsaneDASM64::DASMInst_t> vecDisassembledInst; 
    ArenaAllocator_t allocator(8 * 1024);
    InsaneDASM64::IDASMErrorCode_t iErrCode = InsaneDASM64::DecodeAndDisassemble(vecBytes, vecDisassembledInst, allocator);


    if(iErrCode != InsaneDASM64::IDASMErrorCode_t::IDASMErrorCode_Success)
    {
        LOG("%s", InsaneDASM64::GetErrorMessage(iErrCode));
    }
    else // Printing instructions @ crashed location.
    {
        for(const InsaneDASM64::DASMInst_t& inst : vecDisassembledInst)
        {
            switch(inst.m_nOperands)
            {
                case 0: printf("%10s\n", inst.m_szMnemonic); break;
                case 1: printf("%10s %s\n", inst.m_szMnemonic, inst.m_szOperands[0]); break;
                case 2: printf("%10s %s, %s\n", inst.m_szMnemonic, inst.m_szOperands[0], inst.m_szOperands[1]); break;
                case 3: printf("%10s %s, %s, %s\n", inst.m_szMnemonic, inst.m_szOperands[0], inst.m_szOperands[1], inst.m_szOperands[2]); break;
                case 4: printf("%10s %s, %s, %s, %s\n", 
                                inst.m_szMnemonic, inst.m_szOperands[0], inst.m_szOperands[1], inst.m_szOperands[2], inst.m_szOperands[3]); break;

                default: break;
            }
        }
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::DumpGeneralRegisters(std::fstream& hFile, ucontext_t* pContext)
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
            std::setfill('0') << std::setw(16) << pContext->uc_mcontext.gregs[iRegIndex];

        if(pContext->uc_mcontext.gregs[iRegIndex] == 0)
            hFile << " [ zero ]";

        hFile << std::endl;
    }
    hFile << "------------------------------------------------------------------------------" << std::endl;

    hFile << std::nouppercase << std::dec << std::setfill(' ');
}
