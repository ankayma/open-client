// Bridging header — exposes the agent-ios-ptp C ABI (ankayma_ptp_start/stop) to
// the Swift PacketTunnelProvider. The crate's `include/` dir is on the target's
// HEADER_SEARCH_PATHS (set in project.yml, task #4). [T:A.1.9]
#ifndef PACKETTUNNEL_BRIDGING_HEADER_H
#define PACKETTUNNEL_BRIDGING_HEADER_H

#include "agent_ios_ptp.h"

#endif /* PACKETTUNNEL_BRIDGING_HEADER_H */
