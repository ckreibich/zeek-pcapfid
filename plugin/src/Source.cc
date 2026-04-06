// See the file "COPYING" in the main distribution directory for copyright.

#include "Source.h"

#include "zeek/DebugLogger.h"
#include "zeek/RunState.h"
#include "zeek/iosource/Packet.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

bool PcapFIDSource::ExtractNextPacket(Packet* pkt) {
    auto ret = PcapSource::ExtractNextPacket(pkt);
    return ret;
}

bool PcapFIDSource::ExtractNextPacketInternal() {
    if ( have_packet )
        return true;

    have_packet = false;

    // Don't return any packets if processing is suspended.
    if ( run_state::is_processing_suspended() )
        return false;

    if ( ExtractNextPacket(&current_fid_packet) ) {
        if ( current_fid_packet.time < 0 ) {
            Weird("negative_packet_timestamp", &current_fid_packet);
            return false;
        }

        have_packet = true;
        return true;
    }

    return false;
}

bool PcapFIDSource::GetCurrentPacket(const Packet** pkt) {
    if ( ! have_packet )
        return false;

    *pkt = &current_fid_packet;
    return true;
}

void PcapFIDSource::Process() {
    if ( ! IsOpen() )
        return;

    if ( ! ExtractNextPacketInternal() )
        return;

    run_state::detail::dispatch_packet(&current_fid_packet, this);

    have_packet = false;
    DoneWithPacket();
}

iosource::PktSrc* PcapFIDSource::Instantiate(const std::string& path, bool is_live) {
    return new PcapFIDSource(path, is_live);
}

} // namespace zeek::plugin::Corelight_PcapFIDSource
