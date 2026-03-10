#include "BasicTypes.h"

#include "BlzCompression.h"

#include <algorithm>
#include <cstring>

namespace IdaSwitch
{

/* The following implementation is based on Atmosph�re's kern_k_initial_process_reader.cpp:
   https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_initial_process_reader.cpp
*/

void BlzDecompress(const u8 *in_source, u8 *in_destination, u32 in_source_size)
{
  std::memcpy(in_destination, in_source, in_source_size);
  const u8 *end = (in_destination + in_source_size);

  /* We'll want to prefer `total_size` over `in_source_size`, as `total_size` is a bit different in its value. I'm not sure
     if the difference is consistent, but from one KIP `total_size` == `in_source_size - 3`.
  */
  u32 total_size      = (*reinterpret_cast<const u32 *>(end - 0x0C));
  u32 footer_size     = (*reinterpret_cast<const u32 *>(end - 0x08));
  u32 additional_size = (*reinterpret_cast<const u32 *>(end - 0x04));

  u32 compressed_offset = (total_size - footer_size);
  u8 *compressed_start = ((in_destination + in_source_size) - total_size);
  u32 out_offset = (total_size + additional_size);

  while (out_offset != 0)
  {
    u8 control = compressed_start[--compressed_offset];
    for (u32 i = 0; (i < 8 && out_offset != 0); (i++, control <<= 0x01))
    {
      if ((control & 0x80) == 0)
      {
        compressed_start[--out_offset] = compressed_start[--compressed_offset];
      }
      else
      {
        compressed_offset -= sizeof(u16);
        u16 segment_flags =
          ((compressed_start[compressed_offset + 0] << 0) | (compressed_start[compressed_offset + sizeof(u8)] << 8));

        /* TODO: Try to figure out what this offset of 3 is for. Maybe related to the aforementioned difference between the
           `total_size` and `in_source_size`?
        */
        u32 segment_offset = (((segment_flags >> 0x00) & 0b111111111111) + 3);
        u32 segment_size = std::min(static_cast<u32>(((segment_flags >> 0x0C) & 0b000000001111) + 3), out_offset);

        out_offset -= segment_size;
        std::memcpy(&compressed_start[out_offset], &compressed_start[out_offset + segment_offset], segment_size);
      }
    }
  }

  /* At this point, we've successfully decompressed the buffer. Do note that we don't perform any boundary checks, but this
     shouldn't matter too much for our use case.
  */
}

}
