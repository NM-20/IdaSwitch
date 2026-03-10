#include "BasicTypes.h"
#include "LoadImplementations.h"

#include "IdaSwitch.h"
#include "StringizeHelpers.h"

#include <idaldr.h>
#include <diskio.hpp>

#include <vector>

constexpr IdaSwitch::s32 LOADER_DEFAULT_FILE_FORMAT_NUMBER =
  1;

int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename)
{
  /* The NRO magic is offset to 0x10 due to the RocrtHeader, so we'll have to read in 20 bytes to access it. */
  IdaSwitch::u32 magic[5];
  if (qlread(li, magic, sizeof(magic)) == -1)
    return 0;

  if (magic[4] != '0ORN' && magic[0] != '0OSN' && magic[0] != '1PIK')
    return 0;

  /* This feels REALLY wrong, but it still feels nicer than assigning to a dereference. */
  fileformatname->operator=(
    "Nintendo Switch (v" IDA_SWITCH_STRINGIZE_A(IDA_SWITCH_VERSION) " - " IDA_SWITCH_STRINGIZE_A(IDA_SWITCH_DEVELOPERS) ")");
    
  processor->operator=("ARM");

  return (ACCEPT_FIRST | LOADER_DEFAULT_FILE_FORMAT_NUMBER);
}

void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
  /* Since `accept_file` ensures the given executable is valid, we can skip doing those checks here. */
  int64 size = qlsize(li);

  std::vector<IdaSwitch::u8> buffer;

  /* Does default-initialize each byte, but we need the buffer size to be visible to Load implementations. */
  buffer.resize(size);
  qlread(li, buffer.data(), size);

  /* We still have to check the magic here, however, so we'll cast our buffer pointer to make this easier. */
  auto magic = reinterpret_cast<IdaSwitch::u32 *>(buffer.data());

  if (magic[4] == '0ORN')
  {
    IdaSwitch::LoadNro(buffer);
    return;
  }

  /* After NRO, there's only two other executable types we have to handle, so we only have to explicitly specify one. */
  if (magic[0] == '0OSN')
    IdaSwitch::LoadNso(buffer);
  else
    IdaSwitch::LoadKip(buffer);
}

idaman loader_t ida_module_data LDSC =
  { IDP_INTERFACE_VERSION /* version */, 0 /* flags */, accept_file /* accept_file */, load_file /* load_file */ };
