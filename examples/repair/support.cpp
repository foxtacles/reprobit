#include "shared.h"

extern "C" int support_marker(int value)
{
  return REPAIR_IDENTITY(value) + REPAIR_SUPPORT_BIAS;
}
