// header guard: avoids problems if this file is included twice
#ifndef TUNTONET_H
#define TUNTONET_H

#include "tunToNetUtilities.h"
#include "netToTun.h"

void tunToNetBlastFlavor (contextSimplemux* context);
void tunToNetNoBlastFlavor (contextSimplemux* context);

#endif  // TUNTONET_H