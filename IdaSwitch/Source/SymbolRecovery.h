#pragma once

#include "BasicTypes.h"

#include "Module.h"

#include <pro.h>

#include <cstring>
#include <string_view>
#include <vector>

namespace IdaSwitch
{

/* This structure is based on `ElfSym` from ReSwitched Team's nxo64.py, found at:
   https://github.com/reswitched/loaders/blob/master/nxo64.py
*/
struct ElfSym
{
  std::string_view Name;

  /* Section header table index. */
  u16 Shndx;

  u64 Value;
  u64 Size;
  u8  Vis;
  u8  Type;
  u8  Bind;
  u64 IdbAddress;

  ElfSym(std::string_view in_name, u16 in_shndx, u64 in_value, u64 in_size,
    unsigned char in_other, unsigned char in_info, u64 in_idb_address = 0);
};

struct ElfRel
{
  u64 Offset;
  u32 Type;

  /* The `ElfSym` collection won't be changing once we reach relocations, so we can
     use a pointer in this case.
  */
  const ElfSym *Sym;
  
  s64 Addend;

  ElfRel(u64 in_offset, u32 in_type, const ElfSym *in_sym, s64 in_addend);
};

std::vector<ElfSym> RecoverSymbols(bool in_is_32,
  uval_t in_base, size_t in_bitness, const u8 *in_dynamic, const u8 *in_sections);

}