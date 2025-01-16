cmake_minimum_required(VERSION 3.10)

# Set the project name
project(simplemux)

set(rohc_comp)
set(rohc_decomp)
set(rohc_common)

# Add the executable
add_executable(simplemux buildMuxedPacket.c blastPackets.c commonFunctions.c netToTunUtilities.c netToTun.c tunToNetUtilities.c tunToNet.c periodExpired.c help.c socketRequest.c init.c simplemux.c)

# Add compiler flags
target_compile_options(simplemux PRIVATE -Wall -Wextra)

target_link_libraries(simplemux rohc rohc_comp rohc_decomp rohc_common)
