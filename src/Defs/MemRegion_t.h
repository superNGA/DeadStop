//=========================================================================
//                      Memory Region Handler
//=========================================================================
// by      : INSANE
// created : 08/02/2026
//
// purpose : Stores Memory regions ( start + end format ) in chunks, and provides
//           easy arithmatic operations + bound checks.
//-------------------------------------------------------------------------
#pragma once
#include "../../Include/Alias.h"
#include <vector>
#include <cstdint>



namespace DEADSTOP_NAMESPACE
{
    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    struct MemRegion_t
    {
        MemRegion_t();
        MemRegion_t(uintptr_t iStart, uintptr_t iEnd);

        uintptr_t m_iStart = 0;
        uintptr_t m_iEnd   = 0;
    };


    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    class MemRegionHandler_t
    {
        public:
            MemRegionHandler_t();
            bool InitializeFromFile(const char* szFile);


            MemRegion_t* FindParentRegion(const MemRegion_t& region);
            MemRegion_t* FindParentRegion(uintptr_t iStart, uintptr_t iEnd);
            MemRegion_t* FindParentRegion(uintptr_t iAdrs);

            bool         HasParentRegion(const MemRegion_t& region);
            bool         HasParentRegion(uintptr_t iStart, uintptr_t iEnd);
            bool         HasParentRegion(uintptr_t iAdrs);

            void         RegisterRegion(uintptr_t iStart, uintptr_t iEnd);

            const std::vector<MemRegion_t>& GetAllRegions() const;


        private:
            std::vector<MemRegion_t> m_vecAllRegions;
    };
}
