#include "BasicTypes.h"

#include "LoadImplementations.h"

#include "AddressingConstants.h"
#include "BlzCompression.h"
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

/* The following implementation is based on Atmosphère's kern_k_initial_process_reader.cpp:
   https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_initial_process_reader.cpp
*/
enum KipFlags : u32
{
  KipFlags_TextCompressed    = (1 << 0),
  KipFlags_RoCompressed      = (1 << 1),
  KipFlags_DataCompressed    = (1 << 2),
  KipFlags_64Bit             = (1 << 3),
  KipFlags_64BitAddressSpace = (1 << 4),
  KipFlags_SecureMemory      = (1 << 5),
  KipFlags_Immortal          = (1 << 6),
};

struct KipHeader
{
  u32 Magic;
  u8 Name[12];
  u64 ProgramId;
  u32 Version;
  u8 Priority;
  u8 IdealCoreId;
  u8 Field1e;
  u8 Flags;

  u32 TextOffset;
  u32 TextSize;
  u32 TextFileSize;

  u32 AffinityMask;

  u32 RoOffset;
  u32 RoSize;
  u32 RoFileSize;

  u32 StackSize;

  u32 DataOffset;
  u32 DataSize;
  u32 DataFileSize;

  u32 Field4c;

  u32 BssOffset;
  u32 BssSize;

  u32 Pad[(0x80 - 0x58) / sizeof(u32)];
  u32 Capabilities[0x80 / sizeof(u32)];
};

void LoadKip(const std::vector<u8> &in_buffer)
{
  const u8 *buffer = in_buffer.data();
  auto header = reinterpret_cast<const KipHeader *>(buffer);

  /* Since `.data` is the last of the three segments, we can combine its memory (relative to zero) offset and size to allocate
     a buffer for all three.
  */
  u32 segments_size = (header->DataOffset + header->DataSize);

  std::vector<u8> segments_buffer;
  segments_buffer.reserve(segments_size);

  u8 *segments = segments_buffer.data();

  const u8 *text_file = &buffer[sizeof(KipHeader)];
  const u8 *ro_file = &text_file[header->TextFileSize];
  const u8 *data_file = &ro_file[header->RoFileSize];

  /* Are the segments uncompressed? */
  if (0 == (header->Flags & (KipFlags_DataCompressed | KipFlags_RoCompressed | KipFlags_TextCompressed)))
  {
    std::memcpy(&segments[header->TextOffset], text_file, header->TextSize);

    std::memcpy(&segments[header->RoOffset], ro_file, header->RoSize);

    std::memcpy(&segments[header->DataOffset], data_file, header->DataSize);
  }
  else
  {
    BlzDecompress(text_file,
      (segments + header->TextOffset), header->TextFileSize);

    BlzDecompress(ro_file,
      (segments + header->RoOffset), header->RoFileSize);

    BlzDecompress(data_file,
      (segments + header->DataOffset), header->DataFileSize);
  }

  u8 *text = &segments[header->TextOffset];

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
    found_module = false;
    warning("Could not find MOD0.\nNo symbol recovering!");
  }
  else
  {
    dynamic = (reinterpret_cast<u8 *>(module) + module->DynamicOffset);
    found_module = true;
  }

  /* Compared to NSOs, KIPs have a 64-bit flag, so we do not require the `.dynamic` check we've been using for the former. */
  if ((header->Flags & KipFlags_64Bit) == 0)
  {
    is_32 = true;
    bitness = ADDRESSING_BITNESS_32;
  }
  else
  {
    is_32 = false;
    bitness = ADDRESSING_BITNESS_64;
  }

  ConfigureDatabase(is_32);

  /* Part of `ConfigureDatabase` is setting the base address. Once it's called, we can grab the base address from the IDB. */
  uval_t base = inf_get_baseaddr();

  segment_t *current_segment;

  /* Create the `.text` segment. */
  mem2base(text, 
    (base + header->TextOffset), (base + header->RoOffset), -1);
  
  if (!add_segm(0, (base + header->TextOffset), (base + header->RoOffset), ".text", "CODE"))
    loader_failure("Could not create `.text` segment.\n");

  current_segment = get_segm_by_name(".text");

  current_segment->perm = SEGPERM_EXEC | SEGPERM_READ;
  set_segm_addressing(current_segment, bitness);

  current_segment->update();

  /* Create the `.rodata` segment. */
  mem2base(&segments[header->RoOffset],
    (base + header->RoOffset), (base + header->DataOffset), -1);

  if (!add_segm(0, (base + header->RoOffset), (base + header->DataOffset), ".rodata", "CONST"))
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
  mem2base(&segments[header->DataOffset],
    (base + header->DataOffset), (base + header->DataOffset + header->DataSize), -1);

  if (!add_segm(0, (base + header->DataOffset), (base + header->BssOffset), ".data", "DATA"))
    loader_failure("Could not create `.data` segment.");

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
      if (!add_segm(0, (base + header->BssOffset), (base + header->BssOffset + header->BssSize), ".bss",
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
    if ((module_pointer + module->ExceptionInfoStartOffset) > segments_size)
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

  auto_make_proc(base + header->TextOffset);
}

}
