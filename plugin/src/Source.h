// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/pcap/Source.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

class PcapFIDSource : public zeek::iosource::pcap::PcapSource {
public:
    PcapFIDSource(const std::string& path, bool is_live) : PcapSource(path, is_live) {}
    static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
    bool ExtractNextPacket(Packet* pkt) override;
};

} // namespace zeek::plugin::Corelight_PcapFIDSource
