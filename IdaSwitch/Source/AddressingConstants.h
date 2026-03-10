#pragma once

#include <cstring>

namespace IdaSwitch
{
  
/* These values are used by `set_segm_addressing`, but there aren't any preprocessor defines or constants
   for them. We'll define some for the sake of readability.
*/
constexpr size_t ADDRESSING_BITNESS_32 =
  1;

constexpr size_t ADDRESSING_BITNESS_64 = 
  2;

}
