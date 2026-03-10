#include "BasicTypes.h"

#include "LoadImplementations.h"

#include "AddressingConstants.h"
#include "ConfigureDatabase.h"
#include "Module.h"
#include "SegmentConstants.h"
#include "SymbolRecovery.h"

#include <auto.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <pro.h>
#include <segment.hpp>
#include <segregs.hpp>

#include <cstring>
#include <vector>

namespace IdaSwitch
{

/* The following type implementations are based on https://switchbrew.org/wiki/NRO0. */
struct ModuleHeaderLocation
{
  /* [17.0.0+] Version ([1.0.0-16.1.0] Padding) */
  u32 Version;
  s32 HeaderOffset;

  /* [17.0.0+] */
  s32 VersionOffset;
};

struct RocrtHeader
{
  ModuleHeaderLocation ModuleHeaderLocation;
  u32 Reserved;
};

struct NroHeader
{
  RocrtHeader Rocrt;
  u32 Magic;
  u32 Version;
  u32 Size;
  u32 Flags;

  s32 TextMemoryOffset;
  u32 TextSize;

  s32 RoMemoryOffset;
  u32 RoSize;

  s32 DataMemoryOffset;
  u32 DataSize;

  u32 BssSize;

  u32 Reserved1;

  u8 ModuleId[0x20];

  u32 DsoHandleOffset;

  u32 Reserved2;

  s32 EmbeddedOffset;
  u32 EmbeddedSize;

  s32 DynStrOffset;
  u32 DynStrSize;

  s32 DynSymOffset;
  u32 DynSymSize;
};

void LoadNro(const std::vector<u8> &in_buffer)
{
  /* Compared to NSOs, NROs don't have compressed segments, so we can instead use the memory from `in_buffer` directly in our
     i.e. `mem2base` calls.
  */
  const u8 *buffer = in_buffer.data();
  auto header = reinterpret_cast<const NroHeader *>(buffer);

  const u8 *segments = (buffer + sizeof(NroHeader));

  const u8 *text = &segments[header->TextMemoryOffset];

  u32 module_pointer = header->Rocrt.ModuleHeaderLocation.HeaderOffset;

  size_t bitness;
  const u8 *dynamic = nullptr;
  bool is_32;
  auto module = reinterpret_cast<const ModuleHeader *>(buffer + module_pointer);
  bool found_module;

  /* The `.dynamic` segment only exists if binaries participate in dynamic linking, although I'm not sure if the
     module header is conditionally included. It might, since it's apparently similar to the `PT_DYNAMIC` ELF header,
     which does get excluded.
     The original loader checks if the module header pointer is in range, so we'll do the same just in case.
  */
  if (module_pointer > in_buffer.size() || module->Magic != '0DOM')
  {
    /* We rely on the module header to be able to detect 32-bit executables, so without it, we need to assume the bitness. */
    is_32 = false;
    bitness = ADDRESSING_BITNESS_64;

    found_module = false;

    warning("Could not find MOD0.\nNo symbol recovering!");
  }
  else
  {
    dynamic = (reinterpret_cast<const u8 *>(module) + module->DynamicOffset);

    /* The original loader detects 32-bit executables using the entries in the dynamic segment. On x64, each entry has
       two eight-byte fields, whereas x32 has two four-byte fields.
       Knowing this, the original loader casts the `DT_PLTGOT` and `DT_REL` entries (presumably at fixed locations,
       at least on x32) to unsigned 64-bit integers.
       Since x64 uses eight-byte fields, this cast will return `d_un`. On x32, this will give us the values of `d_tag`
       and `d_un` as a single eight-byte integer.
       Since `d_tag` never exceeds 0xFFFFFFFF, if this casted value exceeds that, it's LIKELY that we're dealing with x32.
    */
    is_32 = (*reinterpret_cast<const u64 *>(&dynamic[DYNAMIC_DT_PLTGOT_OFFSET])) > DYNAMIC_TAG_MAXIMUM ||
      (*reinterpret_cast<const u64 *>(&dynamic[DYNAMIC_DT_REL_OFFSET])) > DYNAMIC_TAG_MAXIMUM;
    bitness = (is_32 ? ADDRESSING_BITNESS_32 : ADDRESSING_BITNESS_64);

    found_module = true;
  }

  ConfigureDatabase(is_32);

  /* Part of `ConfigureDatabase` is setting the base address. Once it's called, we can grab the base address from the IDB. */
  uval_t base = inf_get_baseaddr();

  segment_t *current_segment;

  /* Create the `.text` segment. */
  mem2base(text, 
    (base + header->TextMemoryOffset), (base + header->TextMemoryOffset + header->TextSize), -1);
  
  /* The original loader probably switches from combining the `.text` memory offset and size to the `.rodata` memory offset to
     account for the leading padding `.rodata` may have.
  */
  if (!add_segm(0, (base + header->TextMemoryOffset), (base + header->RoMemoryOffset), ".text", "CODE"))
    loader_failure("Could not create `.text` segment.\n");

  current_segment = get_segm_by_name(".text");

  current_segment->perm = (SEGPERM_EXEC | SEGPERM_READ);
  set_segm_addressing(current_segment, bitness);

  current_segment->update();

  /* Create the `.rodata` segment. */
  mem2base(&segments[header->RoMemoryOffset],
    (base + header->RoMemoryOffset), (base + header->RoMemoryOffset + header->RoSize), -1);

  if (!add_segm(0, (base + header->RoMemoryOffset), (base + header->DataMemoryOffset), ".rodata", "CONST"))
    loader_failure("Could not create `.rodata` segment.");
  
  current_segment = get_segm_by_name(".rodata");

  current_segment->perm = SEGPERM_READ;
  set_segm_addressing(current_segment, bitness);

  current_segment->update();

  /* Create the `.data` segment. */
  mem2base(&segments[header->DataMemoryOffset],
    (base + header->DataMemoryOffset), (base + header->DataMemoryOffset + header->DataSize), -1);

  /* While the loader is able to take the offset of the next segment to define the end of a previous segment, it cannot do this
     for the `.data` segment, as it's the last "real" one.
     As a result, we'll be aligning the end address manually.
  */
  if (!add_segm(0, (base + header->DataMemoryOffset),
    ((base + header->DataMemoryOffset + header->DataSize + SEGMENT_ALIGNMENT) & ~SEGMENT_ALIGNMENT), ".data", "DATA"))
  {
    loader_failure("Could not create `.data` segment.");
  }

  current_segment = get_segm_by_name(".data");

  current_segment->perm = (SEGPERM_READ | SEGPERM_WRITE);
  set_segm_addressing(current_segment, bitness);

  current_segment->update();

  if (found_module)
  {
    /* TODO: Figure out why `BssEndOffset` is restricted to this value specifically. There doesn't seem to be anything related to
       this in any documentation.
    */
    if (module->BssEndOffset <= 0x1FFFFFFF)
    {
      if (!add_segm(0, (base + module_pointer + module->BssStartOffset), (base + module_pointer + module->BssEndOffset), ".bss",
        "BSS"))
      {
        loader_failure("Could not create `.bss` segment.");
      }

      current_segment = get_segm_by_name(".bss");

      current_segment->perm = (SEGPERM_READ | SEGPERM_WRITE);
      set_segm_addressing(current_segment, bitness);

      current_segment->update();
    }
    else
    {
      warning("`.bss` segment is not valid. Skipping...");
    }

    /* While we don't need the symbols returned by this function, we still need to call it to i.e. handle relocations and imports
       for the database.
    */
    RecoverSymbols(is_32, base, bitness, dynamic, segments);
  }

  auto_make_proc(base + header->TextMemoryOffset);
}

}
