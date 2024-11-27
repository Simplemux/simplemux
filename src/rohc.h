// header guard: avoids problems if this file is included twice
#ifndef ROHC_H
#define ROHC_H

#include <rohc/rohc.h>          // for using header compression
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>

#include "commonFunctions.h"

int initRohc(contextSimplemux* context);

#endif // ROHC_H