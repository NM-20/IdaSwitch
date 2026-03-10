#include "BasicTypes.h"

#include <idaldr.h>
#include <typeinf.hpp>

namespace IdaSwitch
{

constexpr u32 DATABASE_X32_BASE_ADDRESS =
  0x60000000;

constexpr u64 DATABASE_X64_BASE_ADDRESS =
  0x7100000000;

void ConfigureDatabase(bool in_is_32)
{
  setinf(INF_DEMNAMES, DEMNAM_GCC3);

  set_compiler_id(COMP_GNU);

  /* `LFLG_PC_FLAT` is 32-bit or higher, so we'll want to set it regardless of `in_is32`. */
  setinf_flag(INF_LFLAGS, LFLG_PC_FLAT);

  if (in_is_32)
  {
    add_til("gnulnx_arm", ADDTIL_INCOMP);

    /* The original loader uses static variables to store bitness and the base address, but
       we can push this functionality to the IDA API.
    */
    setinf(INF_BASEADDR, DATABASE_X32_BASE_ADDRESS);
    setinf(INF_IMAGEBASE, DATABASE_X32_BASE_ADDRESS);
  }
  else
  {
    setinf_flag(INF_LFLAGS, LFLG_64BIT);

    add_til("gnulnx_arm64", ADDTIL_INCOMP);

    setinf(INF_BASEADDR, DATABASE_X64_BASE_ADDRESS);
    setinf(INF_IMAGEBASE, DATABASE_X64_BASE_ADDRESS);
  }
}

}
