// header guard: avoids problems if this file is included twice
#ifndef SOCKETREQUEST_H
#define SOCKETREQUEST_H

#include "commonFunctions.h"
//#include "packetsToSend.h"
//#include "buildMuxedPacket.h"

int socketRequest(contextSimplemux* context, const int on);
int feedbackSocketRequest(contextSimplemux* context);

#endif  // SOCKETREQUEST_H