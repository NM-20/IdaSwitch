#include "BasicTypes.h"

#include "Elf.h"
#include "SegmentConstants.h"
#include "SymbolRecovery.h"

#include <idaldr.h>
#include <kernwin.hpp>
#include <loader.hpp>
#include <netnode.hpp>
#include <offset.hpp>
#include <segment.hpp>

#include <cstring>
#include <map>
#include <string_view>
#include <vector>

namespace IdaSwitch
{

ElfRel::ElfRel(u64 in_offset, u32 in_type, const ElfSym *in_sym, s64 in_addend) : Offset(in_offset), Type(in_type),
  Sym(in_sym), Addend(in_addend)
{
}

ElfSym::ElfSym(
  std::string_view in_name, u16 in_shndx, u64 in_value, u64 in_size, unsigned char in_other, unsigned char in_info,
  u64 in_idb_address)
{
  Name = in_name;
  Shndx = in_shndx;
  Value = in_value;
  Size = in_size;
  Vis = ELF_ST_VISIBILITY(in_other);
  Type = ELF_ST_TYPE(in_info);
  Bind = ELF_ST_BIND(in_info);
  IdbAddress = in_idb_address;
}

std::multimap<Elf64_Sxword, Elf64_Addr> MapDynamicTagsToPointers(bool in_is_32, const u8 *in_dynamic)
{
  /* The original loader seems to use an `std::map` of `d_tag` values to `std::vector` instances, which is due to
     some tags allowing multiple usages.
     We should be able to get this same functionality via an `std::multimap`.
  */
  std::multimap<Elf64_Sxword, Elf64_Addr> result;

  if (in_is_32)
  {
    /* `d_ptr` and `d_val` are both the same size, so we don't really have to worry about which one we choose. */
    for (auto i = reinterpret_cast<const Elf32_Dyn *>(in_dynamic); i->d_tag != DT_NULL; i++)
      result.insert({ i->d_tag, i->d_un.d_ptr });
  }
  else
  {
    /* `d_ptr` and `d_val` are both the same size, so we don't really have to worry about which one we choose. */
    for (auto i = reinterpret_cast<const Elf64_Dyn *>(in_dynamic); i->d_tag != DT_NULL; i++)
      result.insert({ i->d_tag, i->d_un.d_ptr });
  }

  return result;
}

std::vector<ElfSym> GetSymbols(bool in_is_32, const u8 *in_segments,
  Elf64_Addr in_symtab_pointer, const std::multimap<Elf64_Sxword, Elf64_Addr> &in_tag_to_pointers)
{
  std::vector<ElfSym> result;

  /* While the string table and symbol table are both marked as mandatory, we'll double check if they are missing
     just in case.
  */
  std::multimap<Elf64_Sxword, Elf64_Addr>::const_iterator strsz_position = in_tag_to_pointers.find(DT_STRSZ);

  if (strsz_position == in_tag_to_pointers.end())
  {
    warning("String table size was not found!");
    return result;
  }

  Elf64_Addr strsz = strsz_position->second;

  std::multimap<Elf64_Sxword, Elf64_Addr>::const_iterator strtab_pointer_position = in_tag_to_pointers.find(
    DT_STRTAB);

  if (strtab_pointer_position == in_tag_to_pointers.end())
  {
    warning("String table could not be found!");
    return result;
  }

  Elf64_Addr strtab_pointer = strtab_pointer_position->second;
  const u8 *strtab = (in_segments + strtab_pointer);

  if (in_is_32)
  {
    for (auto i = reinterpret_cast<const Elf32_Sym *>(in_segments + in_symtab_pointer); ; i++)
    {
      /* If the symbol table is behind the string table and our iterator is at or has passed the beginning of the
         string table, we've covered all of the symbols.
      */
      if (in_symtab_pointer < strtab_pointer && reinterpret_cast<const u8 *>(i) >= strtab)
        break;

      /* `strsz` is the total size of the string table, and `st_name` is an index into the string table. Here, we
         are checking if the index is in range.
      */
      if (i->st_name > strsz)
        break;

      result.push_back(ElfSym((reinterpret_cast<const char *>(strtab) + i->st_name), i->st_shndx, i->st_value, i->st_size,
        i->st_other, i->st_info));
    }
  }
  else
  {
    for (auto i = reinterpret_cast<const Elf64_Sym *>(in_segments + in_symtab_pointer); ; i++)
    {
      /* If the symbol table is behind the string table and our iterator is at or has passed the beginning of the
         string table, we've covered all of the symbols.
      */
      if (in_symtab_pointer < strtab_pointer && reinterpret_cast<const u8 *>(i) >= strtab)
        break;

      /* `strsz` is the total size of the string table, and `st_name` is an index into the string table. Here, we
         are checking if the index is in range.
      */
      if (i->st_name > strsz)
        break;

      result.push_back(ElfSym((reinterpret_cast<const char *>(strtab) + i->st_name), i->st_shndx, i->st_value, i->st_size,
        i->st_other, i->st_info));
    }
  }

  return result;
}

void ProcessRelocations(bool in_is_32, const u8 *in_segments, Elf64_Sxword in_pointer_tag, Elf64_Sxword in_size_tag,
  const std::vector<ElfSym> &in_symbols,
  const std::multimap<Elf64_Sxword, Elf64_Addr> &in_tag_to_pointers, std::vector<ElfRel> &out_result)
{
  std::multimap<Elf64_Sxword, Elf64_Addr>::const_iterator pointer_position = in_tag_to_pointers.find(in_pointer_tag);
  if (pointer_position == in_tag_to_pointers.cend())
    return;

  std::multimap<Elf64_Sxword, Elf64_Addr>::const_iterator size_position = in_tag_to_pointers.find(in_size_tag);
  if (size_position == in_tag_to_pointers.cend())
    return;

  if (in_is_32)
  {
    /* The original loader and ReSwitched Team's nxo64.py both seem to assume that 32-bit executables do not have
       addends, so we'll do the same.
    */
    Elf64_Addr relocation_count = (size_position->second / sizeof(Elf32_Rel));
    if (relocation_count == 0)
      return;

    auto pointer = reinterpret_cast<const Elf32_Rel *>(in_segments + pointer_position->second);

    for (Elf64_Addr i = 0; i < relocation_count; i++)
    {
      const Elf32_Rel &current = pointer[i];
      out_result.push_back(
        ElfRel(current.r_offset, ELF32_R_TYPE(current.r_info), &in_symbols[ELF32_R_SYM(current.r_info)], 0));
    }
  }
  else
  {
    /* The original loader and ReSwitched Team's nxo64.py both seem to assume that 64-bit executables always have
       addends, so we'll do the same.
    */
    Elf64_Addr relocation_count = (size_position->second / sizeof(Elf64_Rela));
    if (relocation_count == 0)
      return;

    auto pointer = reinterpret_cast<const Elf64_Rela *>(in_segments + pointer_position->second);

    for (Elf64_Addr i = 0; i < relocation_count; i++)
    {
      const Elf64_Rela &current = pointer[i];
      out_result.push_back(ElfRel(current.r_offset,
        ELF64_R_TYPE(current.r_info), &in_symbols[ELF64_R_SYM(current.r_info)], current.r_addend));
    }
  }
}

void AddToImportsView(const std::string_view &in_name, ea_t in_address)
{
  netnode node;
  node.create();
  node.supset(in_address, in_name.data(), 0);
  import_module("", nullptr, node, nullptr, "switch");
}

std::vector<ElfSym> RecoverSymbols(bool in_is_32, uval_t in_base, size_t in_bitness, const u8 *in_dynamic, const u8 *in_segments)
{
  std::multimap<Elf64_Sxword, Elf64_Addr> tag_to_pointers = MapDynamicTagsToPointers(in_is_32, in_dynamic);
  std::multimap<Elf64_Sxword, Elf64_Addr>::iterator symtab_pointer_position = tag_to_pointers.find(DT_SYMTAB);

  if (symtab_pointer_position == tag_to_pointers.end())
  {
    warning("No symbol table found!");
    return std::vector<ElfSym>();
  }

  /* Otherwise, we can proceed with handling symbols. We'll need to conditionally handle this based on whether we
     are dealing with a 32-bit executable.
  */
  std::vector<ElfSym> symbols = GetSymbols(in_is_32, in_segments, symtab_pointer_position->second, tag_to_pointers);
  
  std::vector<ElfRel> relocations;

  ProcessRelocations(in_is_32, in_segments, DT_REL, DT_RELSZ, symbols, tag_to_pointers, relocations);
  ProcessRelocations(in_is_32, in_segments, DT_RELA, DT_RELASZ, symbols, tag_to_pointers, relocations);
  ProcessRelocations(in_is_32, in_segments, DT_JMPREL, DT_PLTRELSZ, symbols, tag_to_pointers, relocations);

  u32 undefined_count = 0;
  for (const ElfSym &current : symbols)
  {
    if (current.Shndx == SHN_UNDEF && !current.Name.empty())
      undefined_count++;
  }

  /* Create the `Imports` segment. */
  segment_t *bss_segment = get_segm_by_name(".bss");

  /* We can only reach this point if the BSS segment was successfully created, so it is safe for us to omit a null
     check.
  */

  ea_t pointer_size;
  flags64_t pointer_flags;

  if (in_is_32)
  {
    pointer_size = sizeof(u32);
    pointer_flags = dword_flag();
  }
  else
  {
    pointer_size = sizeof(u64);
    pointer_flags = qword_flag();
  }

  ea_t imports_start = (((bss_segment->end_ea + SEGMENT_ALIGNMENT) & ~SEGMENT_ALIGNMENT) + pointer_size);

  if (!add_segm(0, imports_start, (imports_start + (undefined_count * pointer_size)), "Imports", "XTRN"))
    loader_failure("Could not create `Imports` segment.");

  segment_t *imports_segment = get_segm_by_name("Imports");
  
  imports_segment->perm = SEGPERM_READ;
  set_segm_addressing(imports_segment, in_bitness);

  imports_segment->update();

  /* Now, we can work on applying the symbol names we've retrieved. */
  ea_t current_import = imports_start;
  for (ElfSym &current : symbols)
  {
    if (current.Shndx != SHN_UNDEF)
    {
      /* In this case, we are not dealing with an import, so we only have functions and data to work with here. */
      uval_t symbol_address = (in_base + current.Value);
      if (current.Type == STT_FUNC)
      {
        add_entry(symbol_address, symbol_address, current.Name.data(), false);
        auto_make_proc(symbol_address);
        current.IdbAddress = symbol_address;
      }
      else
      {
        set_name(symbol_address, current.Name.data(), (SN_FORCE | SN_NOCHECK | SN_PUBLIC));
      }
    }
    else
    {
      /* Otherwise, we're likely dealing with an import. We'll need to ensure that it's a valid one by checking if
         it has a name.
      */
      if (current.Name.empty())
        continue;

      create_data(current_import, pointer_flags, pointer_size, BADNODE);
      op_plain_offset(current_import, 0, 0);
      set_name(current_import, current.Name.data(), (SN_FORCE | SN_NODUMMY | SN_NOCHECK | SN_NON_PUBLIC));
      
      current.IdbAddress = current_import;
      AddToImportsView(current.Name, current_import);

      /* The original loader increases the current import address before appending it to the IDB's Imports view,
         which causes it to be offset by four or eight (depending on the executable architecture).
         We can fix this by moving the increase after the `AddToImportsView` call has finished executing.
      */
      current_import += pointer_size;
    }
  }

  /* Finally, we'll need to handle relocations. */
  for (const ElfRel &current : relocations)
  {
    uval_t relocation_address = (in_base + current.Offset);
    if (current.Type < R_AARCH64_ABS64)
    {
      if (current.Type == R_ARM_ABS32 || current.Type == R_ARM_GLOB_DAT || current.Type == R_ARM_JUMP_SLOT)
        put_dword(relocation_address, current.Sym->IdbAddress);
      else if (current.Type == R_ARM_RELATIVE)
        put_dword(relocation_address, (relocation_address + get_dword(relocation_address)));
    }
    else
    {
      if (current.Type == R_AARCH64_RELATIVE)
        put_qword(relocation_address, (in_base + current.Addend));
      else if (current.Type == R_AARCH64_ABS64 || current.Type == R_AARCH64_GLOB_DAT || current.Type == R_AARCH64_JUMP_SLOT)
        put_qword(relocation_address, (current.Sym->IdbAddress + current.Addend));
    }

    create_data(relocation_address, pointer_flags, pointer_size, BADNODE);
    op_plain_offset(relocation_address, 0, 0);
  }

  /* We've successfully recovered symbols, so we can now return. From there, we can i.e. search for `nnMain`, then
     define it as the entrypoint in the IDB.
  */
  return symbols;
}

}
