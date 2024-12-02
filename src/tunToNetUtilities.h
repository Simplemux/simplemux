// header guard: avoids problems if this file is included twice
#ifndef TUNTONETUTILITIES_H
#define TUNTONETUTILITIES_H

#include "commonFunctions.h"
#include "buildMuxedPacket.h"

bool checkPacketSize (contextSimplemux* context, uint16_t size);

void compressPacket(contextSimplemux* context, uint16_t size);

int allSameProtocol(contextSimplemux* context);

void emptyBufferIfNeeded(contextSimplemux* context, int single_protocol);

void createSimplemuxSeparatorNormal(contextSimplemux* context);

void createSimplemuxSeparatorFast(contextSimplemux* context);

int addSizeOfProtocolField(contextSimplemux* context);

#ifdef DEBUG
  void debugInformationAboutTrigger(contextSimplemux* context,
                                    int single_protocol,
                                    uint64_t time_difference);
#endif


#endif