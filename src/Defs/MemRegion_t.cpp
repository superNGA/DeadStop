//=========================================================================
//                      Memory Region Handler
//=========================================================================
// by      : INSANE
// created : 08/02/2026
//
// purpose : Stores Memory regions ( start + end format ) in chunks, and provides
//           easy arithmatic operations + bound checks.
//-------------------------------------------------------------------------
#include "MemRegion_t.h"
#include "../Util/Assertion/Assertion.h"
#include <fstream>


// Mind this...
using namespace DeadStop;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegion_t::MemRegion_t()
{
    m_iStart = 0; m_iEnd = 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegion_t::MemRegion_t(uintptr_t iStart, uintptr_t iEnd)
{
    m_iStart = iStart; m_iEnd = iEnd;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegionHandler_t::MemRegionHandler_t()
{
    m_vecAllRegions.clear();
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop::MemRegionHandler_t::InitializeFromFile(const char* szFile)
{
    assertion(szFile != nullptr && "Invalid file");
    
    std::ifstream hMaps(szFile);

    // If we can't open this, something must be really wrong.
    if(hMaps.is_open() == false)
        return false;


    std::string szLine;
    while(std::getline(hMaps, szLine))
    {
        // /proc/self/maps should have "[startadrs]-[EndAdrs]" format.
        
        uintptr_t iStartAdrs = 0;
        uintptr_t iEndAdrs   = 0;

        size_t iterator = 0;
        size_t nChars = szLine.size();

        // Discarding leading spaces.
        while(iterator < nChars && szLine[iterator] == ' ') iterator++;

        // Get the first hex number from string.
        for(; iterator < nChars; iterator++)
        {
            char c = szLine[iterator];
            int iNum = 0;


            if(c >= '0' && c <= '9')
                iNum = c - '0';
            else if(c >= 'A' && c <= 'F')
                iNum = c - 'A' + 10;
            else if(c >= 'a' && c <= 'f')
                iNum = c - 'a' + 10;
            else break;

            iStartAdrs *= 0x10;
            iStartAdrs += iNum;
        }

        // So we are past whatever character cause "break;" in the loop above.
        iterator++;


        // Get the second hex number from string.
        for(; iterator < nChars; iterator++)
        {
            char c = szLine[iterator];
            int iNum = 0;


            if(c >= '0' && c <= '9')
                iNum = c - '0';
            else if(c >= 'A' && c <= 'F')
                iNum = c - 'A' + 10;
            else if(c >= 'a' && c <= 'f')
                iNum = c - 'a' + 10;
            else break;

            iEndAdrs *= 0x10;
            iEndAdrs += iNum;
        }

        // Store em in "out" array.
        RegisterRegion(iStartAdrs, iEndAdrs);
    }


    hMaps.close();
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegion_t* DeadStop::MemRegionHandler_t::FindParentRegion(const MemRegion_t& region)
{
    assertion(region.m_iStart <= region.m_iEnd && "Invalid Memory Regoin.");

    for(MemRegion_t& parentRegion : m_vecAllRegions)
    {
        // NOTE : End address of a memory region is not included according to /proc/self/maps.
        //        Hence is not part of the memory region.
        bool bStartValid = region.m_iStart >= parentRegion.m_iStart && region.m_iStart < parentRegion.m_iEnd;
        bool bEndValid   = region.m_iEnd   >= parentRegion.m_iStart && region.m_iEnd   < parentRegion.m_iEnd;

        if(bStartValid == true && bEndValid == true)
            return &parentRegion;
    }

    return nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegion_t* DeadStop::MemRegionHandler_t::FindParentRegion(uintptr_t iStart, uintptr_t iEnd)
{
    return FindParentRegion(MemRegion_t(iStart, iEnd));
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
DeadStop::MemRegion_t* DeadStop::MemRegionHandler_t::FindParentRegion(uintptr_t iAdrs)
{
    return FindParentRegion(MemRegion_t(iAdrs, iAdrs));
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop::MemRegionHandler_t::HasParentRegion(const MemRegion_t& region)
{
    return FindParentRegion(region) != nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop::MemRegionHandler_t::HasParentRegion(uintptr_t iStart, uintptr_t iEnd)
{
    return FindParentRegion(iStart, iEnd) != nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool DeadStop::MemRegionHandler_t::HasParentRegion(uintptr_t iAdrs)
{
    return FindParentRegion(iAdrs) != nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void DeadStop::MemRegionHandler_t::RegisterRegion(uintptr_t iStart, uintptr_t iEnd)
{
    m_vecAllRegions.push_back(MemRegion_t(iStart, iEnd));
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
const std::vector<MemRegion_t>& DeadStop::MemRegionHandler_t::GetAllRegions() const
{
    return m_vecAllRegions;
}
