#pragma once

#include "BasicTypes.h"

namespace IdaSwitch
{

/* The following type implementations are based on https://switchbrew.org/wiki/MOD. */
struct ModuleHeader
{
  u32 Magic;

  s32 DynamicOffset;

  s32 BssStartOffset;
  s32 BssEndOffset;

  s32 ExceptionInfoStartOffset;
  s32 ExceptionInfoEndOffset;

  /* Offset to runtime-generated module object, typically equal to `.bss` base. */
  s32 ModuleOffset;

  /* [19.0.0+] */
  s32 RelroStartOffset;
  s32 FullRelroEndOffset;
  s32 NxDebugLinkStartOffset;
  s32 NxDebugLinkEndOffset;
  s32 NoteGnuBuildIdStartOffset;
  s32 NoteGnuBuildIdEndOffset;
};

}
