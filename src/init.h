// header guard: avoids problems if this file is included twice
#ifndef INIT_H
#define INIT_H

#include "commonFunctions.h"
#include "help.h"

void initContext(contextSimplemux* context);
void parseCommandLine(int argc, char *argv[], contextSimplemux* context);
int checkCommandLineOptions(int argc, char *progname, contextSimplemux* context);
void initTunTapInterface(contextSimplemux* context);
void initSizeMax(contextSimplemux* context);
void initTriggerParameters(contextSimplemux* context);
void initBlastFlavor(contextSimplemux* context);

#endif    // INIT_H