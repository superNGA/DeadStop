//=========================================================================
//                      DeadStop Implementation
//=========================================================================
// by      : INSANE
// created : 05/02/2026
//
// purpose : DeadStop's core logic
//-------------------------------------------------------------------------
#pragma once
#include "../Include/Alias.h"
#include "../Include/DeadStop.h"
#include <string>
#include <signal.h>



namespace DEADSTOP_NAMESPACE
{
    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    class DeadStop_t
    {
        public:
            // Singleton instance getter.
            static DeadStop_t& GetInstance() { static DeadStop_t instance; return instance; }

            ErrCodes_t Initialize(
                 const char* szDumpFilePath, int iAsmDumpRangeinBytes, int iStringDumpSize, int iCallStackDepth, int iSignatureSize);
            ErrCodes_t Uninitialize();

            bool IsInitialized() const;
            const std::string& GetDumpFilePath() const;
            int GetAsmDumpRange()   const;
            int GetStringDumpSize() const;
            int GetCallStackDepth() const;
            int GetSignatureSize()  const;

        private:
            // Singleton.
            DeadStop_t();
            DeadStop_t(const DeadStop_t& other) = delete;


            bool        m_bInitialized = false;
            std::string m_szDumpFilePath;


            // Output properties...
            int         m_iAsmDumpRange   = 0;
            int         m_iStringDumpSize = 0;
            int         m_iCallStackDepth = 0;
            int         m_iSignatureSize  = 0;

            struct sigaction m_sigAction;
    };
}
