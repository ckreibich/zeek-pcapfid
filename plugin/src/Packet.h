// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

class FIDPacket : public zeek::Packet {
public:
    FIDPacket(int link_type, pkt_timeval* ts, uint32_t caplen, uint32_t len, const u_char* data, bool copy = false,
              std::string tag = "")
        : zeek::Packet(link_type, ts, caplen, len, data, copy, tag) {
        flow_id = 0;
    }
    FIDPacket() : zeek::Packet() { flow_id = 0; }

    uint32_t flow_id;
};

} // namespace zeek::plugin::Corelight_PcapFIDSource
