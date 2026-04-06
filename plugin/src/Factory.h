// See the file "COPYING" in the toplevel directory.
#pragma once

#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

class Factory : public zeek::conn_key::fivetuple::Factory {
public:
    static zeek::conn_key::FactoryPtr Instantiate() { return std::make_unique<Factory>(); }

private:
    /**
     * Instantiates a clean ConnKey derivative and returns it.
     *
     * @return A unique pointer to the ConnKey instance.
     */
    zeek::ConnKeyPtr DoNewConnKey() const override;

    /**
     * Instantiates a filled-in ConnKey derivative from a script-layer
     * record, usually a conn_id instance.
     *
     * @param v The script-layer value providing key input.
     * @return A unique pointer to the ConnKey instance, or an error message.
     */
    zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const override;
};

} // namespace zeek::plugin::Corelight_PcapFIDSource
