#pragma once

#include "BasicTypes.h"

namespace IdaSwitch
{

/* These tag names were determined from the System V Application Binary Interface's specification for the ELF
   `.dynamic` segment:
   https://refspecs.linuxfoundation.org/elf/gabi41.pdf
*/
constexpr s64 DYNAMIC_DT_PLTGOT_OFFSET =
  0x00;

constexpr s64 DYNAMIC_DT_REL_OFFSET =
  0x20;

/* The ELF standard does define this as 0x7FFFFFFF, but the original loader checks for 0xFFFFFFFF. Maybe this
   is something Switch-specific? Regardless, we'll use the original loader's constant just to be safe.
*/
constexpr u64 DYNAMIC_TAG_MAXIMUM =
  0xFFFFFFFF;

/* This is really the page size on Switch, albeit deducted by one to prevent a size of zero from being aligned. */
constexpr u64 SEGMENT_ALIGNMENT =
  0x1000 - 0x0001;

/* The `.text` segment, at offset 0x04, holds a pointer to the module header: https://switchbrew.org/wiki/Rtld. */
constexpr s64 TEXT_MODULE_HEADER_POINTER_OFFSET =
  0x04;

}
