// header guard: avoids problems if this file is included twice
#ifndef SOCKETREQUEST_H
#define SOCKETREQUEST_H

#include "commonFunctions.h"

int socketRequest(contextSimplemux* context, const int on);

#ifdef USINGROHC
  int feedbackSocketRequest(contextSimplemux* context);
#endif

#endif  // SOCKETREQUEST_H