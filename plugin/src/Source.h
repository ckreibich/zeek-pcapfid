// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/pcap/Source.h"

#include "Packet.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

class PcapFIDSource : public zeek::iosource::pcap::PcapSource {
public:
    PcapFIDSource(const std::string& path, bool is_live) : PcapSource(path, is_live) { have_packet = false; }
    bool GetCurrentPacket(const Packet** hdr);

    static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
    bool ExtractNextPacket(Packet* pkt) override;

private:
    // Internal helper for ExtractNextPacket().
    bool ExtractNextPacketInternal();

    void Process() override;

    bool have_packet;
    FIDPacket current_fid_packet;
};

} // namespace zeek::plugin::Corelight_PcapFIDSource
