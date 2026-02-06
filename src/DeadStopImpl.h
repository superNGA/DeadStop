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


            ErrCodes_t Initialize(const char* m_szDumpFilePath);
            ErrCodes_t Uninitialize();

        private:
            // Singleton.
            DeadStop_t();
            DeadStop_t(const DeadStop_t& other) = delete;


            bool        m_bInitialized = false;
            std::string m_szDumpFilePath;

            struct sigaction m_sigAction;
    };
}
