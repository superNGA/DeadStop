//=========================================================================
//                      Signal Handler
//=========================================================================
// by      : INSANE
// created : 06/02/2026
//
// purpose : Handler roughly all common signals received from OS.
//-------------------------------------------------------------------------
#include "SignalHandler.h"

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
    static void SignalHandler_SIGINT (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGILL (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGABRT(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGFPE (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGSEGV(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGTERM(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGHUP (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGQUIT(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGTRAP(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGKILL(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGPIPE(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
    static void SignalHandler_SIGALRM(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext);
}




///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void DeadStop::MasterSignalHandler(int iSignalID, siginfo_t* pSigInfo, void* pContext)
{
    ucontext_t* pUContext = reinterpret_cast<ucontext_t*>(pContext);

    switch(iSignalID)
    {
        case SIGINT:  SignalHandler_SIGINT (iSignalID, pSigInfo, pUContext); break;
        case SIGILL:  SignalHandler_SIGILL (iSignalID, pSigInfo, pUContext); break;
        case SIGABRT: SignalHandler_SIGABRT(iSignalID, pSigInfo, pUContext); break;
        case SIGFPE:  SignalHandler_SIGFPE (iSignalID, pSigInfo, pUContext); break;
        case SIGSEGV: SignalHandler_SIGSEGV(iSignalID, pSigInfo, pUContext); break; 
        case SIGTERM: SignalHandler_SIGTERM(iSignalID, pSigInfo, pUContext); break;
        case SIGHUP:  SignalHandler_SIGHUP (iSignalID, pSigInfo, pUContext); break;
        case SIGQUIT: SignalHandler_SIGQUIT(iSignalID, pSigInfo, pUContext); break;
        case SIGTRAP: SignalHandler_SIGTRAP(iSignalID, pSigInfo, pUContext); break;
        case SIGKILL: SignalHandler_SIGKILL(iSignalID, pSigInfo, pUContext); break;
        case SIGPIPE: SignalHandler_SIGPIPE(iSignalID, pSigInfo, pUContext); break;
        case SIGALRM: SignalHandler_SIGALRM(iSignalID, pSigInfo, pUContext); break;

        default: return; // What is this signal for?
    }
}



static void DeadStop::SignalHandler_SIGINT (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGILL (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGABRT(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGFPE (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DeadStop::SignalHandler_SIGSEGV(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext)
{
    // Must be only segment fault for now.
    assertion(iSignalID == SIGSEGV && "Received signal is not for segfault.");


    LOG("Signal Index : %d, SigInfo : %p, Context : %p", iSignalID, pSigInfo, pUContext);


    // What adrs cause segfault.
    LOG("Faulted 4 adrs : %p", pSigInfo->si_addr);
    LOG("rip : %p, rsp : %p, rbp : %p", 
            pUContext->uc_mcontext.gregs[REG_RIP],
            pUContext->uc_mcontext.gregs[REG_RSP],
            pUContext->uc_mcontext.gregs[REG_RBP]);


    void* pCrashLocation = reinterpret_cast<void*>(pUContext->uc_mcontext.gregs[REG_RIP]);


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


    abort();
}


static void DeadStop::SignalHandler_SIGTERM(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGHUP (int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGQUIT(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGTRAP(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGKILL(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGPIPE(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
static void DeadStop::SignalHandler_SIGALRM(int iSignalID, siginfo_t* pSigInfo, ucontext_t* pUContext) {return;}
