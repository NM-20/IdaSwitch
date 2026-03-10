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

#include <lz4.h>

#include <cstring>
#include <vector>

namespace IdaSwitch
{

/* The following type implementations are based on https://switchbrew.org/wiki/NSO0. */
enum NsoFlags : u32
{
  /* `.text` section is compressed. */
  NsoFlags_TextCompress = (1 << 0),

  /* `.rodata` section is compressed. */
  NsoFlags_RoCompress = (1 << 1),

  /* `.data` section is compressed. */
  NsoFlags_DataCompress = (1 << 2),

  /* `.text` hash must be checked when loading. */
  NsoFlags_TextHash = (1 << 3),

  /* `.rodata` hash must be checked when loading. */
  NsoFlags_RoHash = (1 << 4),

  /* `.data` hash must be checked when loading. */
  NsoFlags_DataHash = (1 << 5),
};

struct NsoHeader
{
  u32 Magic;
  u32 Version;

  u32 Reserved1;

  /* Corresponds to `NsoFlags`. */
  u32 Flags;

  s32 TextFileOffset;
  s32 TextMemoryOffset;
  u32 TextSize;

  /* Calculated by `sizeof(NsoHeader)`. */
  s32 ModuleNameOffset;

  s32 RoFileOffset;
  s32 RoMemoryOffset;
  u32 RoSize;

  u32 ModuleNameSize;

  s32 DataFileOffset;
  s32 DataMemoryOffset;
  u32 DataSize;

  u32 BssSize;

  u8 ModuleId[0x20];

  /* `.text` compressed size. */
  u32 TextFileSize;

  /* `.rodata` compressed size. */
  u32 RoFileSize;

  /* `.data` compressed size. */
  u32 DataFileSize;

  u8 Reserved2[0x1C];

  /* Relative to the `.rodata` section. */
  s32 EmbeddedOffset;
  u32 EmbeddedSize;

  /* Relative to the `.rodata` section. */
  s32 DynStrOffset;
  u32 DynStrSize;

  /* Relative to the `.rodata` section. */
  s32 DynSymOffset;
  u32 DynSymSize;

  /* SHA-256 hash over the decompressed `.text` section using the above size. */
  u8 TextHash[0x20];

  /* SHA-256 hash over the decompressed `.rodata` section using the above size. */
  u8 RoHash[0x20];

  /* SHA-256 hash over the decompressed `.data` section using the above size. */
  u8 DataHash[0x20];

  /* Variable-sized data: Compressed sections. */
};

void LoadNso(const std::vector<u8> &in_buffer)
{
  const u8 *buffer = in_buffer.data();
  auto header = reinterpret_cast<const NsoHeader *>(buffer);

  /* Since `.data` is the last of the three segments, we can combine its memory (relative to zero) offset and size to allocate
     a buffer for all three.
  */
  u32 segments_size = (header->DataMemoryOffset + header->DataSize);

  std::vector<u8> segments_buffer;
  segments_buffer.reserve(segments_size);

  u8 *segments = segments_buffer.data();

  /* Are the segments uncompressed? */
  if (0 == (header->Flags & (NsoFlags_DataCompress | NsoFlags_RoCompress | NsoFlags_TextCompress)))
  {
    std::memcpy(&segments[header->TextMemoryOffset], &buffer[header->TextFileOffset], header->TextSize);

    std::memcpy(&segments[header->RoMemoryOffset], &buffer[header->RoFileOffset], header->RoSize);

    std::memcpy(&segments[header->DataMemoryOffset], &buffer[header->DataFileOffset], header->DataSize);
  }
  else
  {
    LZ4_decompress_safe(reinterpret_cast<const char *>(buffer + header->TextFileOffset),
      reinterpret_cast<char *>(segments + header->TextMemoryOffset), header->TextFileSize, header->TextSize);

    LZ4_decompress_safe(reinterpret_cast<const char *>(buffer + header->RoFileOffset),
      reinterpret_cast<char *>(segments + header->RoMemoryOffset), header->RoFileSize, header->RoSize);

    LZ4_decompress_safe(reinterpret_cast<const char *>(buffer + header->DataFileOffset),
      reinterpret_cast<char *>(segments + header->DataMemoryOffset), header->DataFileSize, header->DataSize);
  }

  u8 *text = &segments[header->TextMemoryOffset];

  u32 module_pointer = (*reinterpret_cast<u32 *>(text + TEXT_MODULE_HEADER_POINTER_OFFSET));

  size_t bitness;
  u8 *dynamic = nullptr;
  bool is_32;
  auto module = reinterpret_cast<ModuleHeader *>(text + module_pointer);
  bool found_module;

  /* The `.dynamic` segment only exists if binaries participate in dynamic linking, although I'm not sure if the
     module header is conditionally included. It might, since it's apparently similar to the `PT_DYNAMIC` ELF header,
     which does get excluded.
     The original loader checks if the module header pointer is in range, so we'll do the same just in case.
  */
  if (module_pointer > segments_size || module->Magic != '0DOM')
  {
    /* We rely on the module header to be able to detect 32-bit executables, so without it, we need to assume the bitness. */
    is_32 = false;
    bitness = ADDRESSING_BITNESS_64;

    found_module = false;

    warning("Could not find MOD0.\nNo symbol recovering!");
  }
  else
  {
    dynamic = (reinterpret_cast<u8 *>(module) + module->DynamicOffset);

    /* The original loader detects 32-bit executables using the entries in the dynamic segment. On x64, each entry has
       two eight-byte fields, whereas x32 has two four-byte fields.
       Knowing this, the original loader casts the `DT_PLTGOT` and `DT_REL` entries (presumably at fixed locations,
       at least on x32) to unsigned 64-bit integers.
       Since x64 uses eight-byte fields, this cast will return `d_un`. On x32, this will give us the values of `d_tag`
       and `d_un` as a single eight-byte integer.
       Since `d_tag` never exceeds 0xFFFFFFFF, if this casted value exceeds that, it's LIKELY that we're dealing with x32.
    */
    is_32 = (*reinterpret_cast<u64 *>(&dynamic[DYNAMIC_DT_PLTGOT_OFFSET])) > DYNAMIC_TAG_MAXIMUM ||
      (*reinterpret_cast<u64 *>(&dynamic[DYNAMIC_DT_REL_OFFSET])) > DYNAMIC_TAG_MAXIMUM;
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

  current_segment->perm = SEGPERM_EXEC | SEGPERM_READ;
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

  /* We MIGHT be able to move this into `ConfigureDatabase`, but I feel like there MIGHT be some obscure reason why this is set
     specifically here. We'll keep it the same to avoid a headache.
  */
  setinf(INF_START_CS, 0);

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

  /* TODO: Figure out how this API works. The original loader specifies a constant value (1), but I'm not sure how it retrieved
     that value.
  */
  set_default_dataseg(1);

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
    
    /* Next, create the `eh_frame_hdr` segment.` */
    if (module->ExceptionInfoStartOffset != 0)
    {
      if (!add_segm(0,
        (base + module_pointer + module->ExceptionInfoStartOffset), (base + module_pointer + module->ExceptionInfoEndOffset),
        ".eh_frame_hdr", "CONST"))
      {
        loader_failure("Could not create `.eh_frame_hdr` segment.");
      }

      current_segment = get_segm_by_name(".eh_frame_hdr");

      current_segment->perm = SEGPERM_READ;
      set_segm_addressing(current_segment, bitness);

      current_segment->update();
    }

    std::vector<ElfSym> symbols = RecoverSymbols(is_32, base, bitness, dynamic, segments);
    
    /* While the original loader does this after the `auto_make_proc` calls below, we'll move it here to align it with the other
       symbol handling.
    */
    for (const ElfSym &current : symbols)
    {
      if (current.Name == "nnMain")
      {
        setinf(INF_START_IP, (base + current.Value));
        break;
      }
    }
  }

  auto_make_proc(base + header->TextMemoryOffset);
}

}
