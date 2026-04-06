// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/Packet.h"
#include "Source.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

bool PcapFIDSource::ExtractNextPacket(Packet* pkt) {
    return PcapSource::ExtractNextPacket(pkt);
}

iosource::PktSrc* PcapFIDSource::Instantiate(const std::string& path, bool is_live) {
    return new PcapFIDSource(path, is_live);
}

} // namespace zeek::plugin::Corelight_PcapFIDSource
