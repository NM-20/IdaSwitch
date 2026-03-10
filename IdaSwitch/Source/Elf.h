#pragma once

#include <cstdint>

namespace IdaSwitch
{

/* This header references the following specifications:
   https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html
   https://refspecs.linuxfoundation.org/elf/ARMELF.pdf
   https://refspecs.linuxfoundation.org/elf/gabi41.pdf
   https://www.man7.org/linux/man-pages/man5/elf.5.html
*/

typedef uint32_t Elf32_Addr;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef uint64_t Elf64_Addr;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Xword;
typedef uint32_t Elf64_Word;

constexpr Elf64_Sxword DT_JMPREL =
  23;

constexpr Elf64_Sxword DT_NULL =
  0;

constexpr Elf64_Sxword DT_PLTRELSZ =
  2;

constexpr Elf64_Sxword DT_REL =
  17;

constexpr Elf64_Sxword DT_RELA =
  7;

constexpr Elf64_Sxword DT_RELASZ =
  8;

constexpr Elf64_Sxword DT_RELSZ =
  18;

constexpr Elf64_Sxword DT_STRSZ =
  10;

constexpr Elf64_Sxword DT_STRTAB =
  5;

constexpr Elf64_Sxword DT_SYMTAB =
  6;

/* From SwitchBrew's Rtld documentation: https://switchbrew.org/wiki/Rtld */
constexpr u32 R_AARCH64_ABS32 =
  258;

constexpr u32 R_AARCH64_ABS64 =
  257;


constexpr u32 R_AARCH64_GLOB_DAT =
  1025;

constexpr u32 R_AARCH64_JUMP_SLOT =
  1026;

constexpr u32 R_AARCH64_RELATIVE =
  1027;

constexpr u32 R_ARM_ABS32 =
  2;

constexpr u32 R_ARM_GLOB_DAT =
  21;

constexpr u32 R_ARM_JUMP_SLOT =
  22;

constexpr u32 R_ARM_RELATIVE =
  23;

constexpr uint16_t SHN_UNDEF =
  0;

constexpr u8 STT_FUNC =
  2;

/* These are the same for both Elf32 and Elf64, so we've omitted the bitness. */
#define ELF32_R_SYM(i) \
  ((i) >> 8)
  
#define ELF32_R_TYPE(i) \
  ((unsigned char)(i))

#define ELF64_R_SYM(i) \
  ((i) >> 32)
#define ELF64_R_TYPE(i) \
  ((Elf64_Word)(i))

#define ELF_ST_BIND(i) \
  ((i) >> 4)
#define ELF_ST_TYPE(i) \
  ((i) & 0x0F)

#define ELF_ST_VISIBILITY(o) \
  ((o) & 0x03)

struct Elf32_Dyn
{
  Elf32_Sword d_tag;
  union
  {
    Elf32_Word d_val;
    Elf32_Addr d_ptr;
  } d_un;
};

struct Elf32_Rel
{
  Elf32_Addr r_offset;
  uint32_t   r_info;
};

struct Elf32_Sym
{
  uint32_t      st_name;
  Elf32_Addr    st_value;
  uint32_t      st_size;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t      st_shndx;
};

struct Elf64_Dyn
{
  Elf64_Sxword d_tag;
  union
  {
    Elf64_Xword d_val;
    Elf64_Addr  d_ptr;
  } d_un;
};

struct Elf64_Rela
{
  Elf64_Addr r_offset;
  uint64_t   r_info;
  int64_t    r_addend;
};

struct Elf64_Sym
{
  uint32_t      st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t      st_shndx;
  Elf64_Addr    st_value;
  uint64_t      st_size;
};
  
}
