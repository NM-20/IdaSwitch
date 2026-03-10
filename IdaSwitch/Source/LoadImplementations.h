#pragma once

#include "BasicTypes.h"

#include <vector>

namespace IdaSwitch
{

void LoadKip(const std::vector<u8> &in_buffer);
void LoadNro(const std::vector<u8> &in_buffer);
void LoadNso(const std::vector<u8> &in_buffer);

}
