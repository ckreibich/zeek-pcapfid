// See the file "COPYING" in the toplevel directory for copyright.

#include "Factory.h"
#include "Packet.h"

#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"

namespace zeek::plugin::Corelight_PcapFIDSource {

class FlowIDConnKey : public zeek::IPBasedConnKey {
public:
    FlowIDConnKey() {
        // Ensure padding holes in the key struct are filled with zeroes.
        memset(static_cast<void*>(&key), 0, sizeof(key));
    }

    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }
    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key), session::detail::Key::CONNECTION_KEY_TYPE};
    }

    void DoPopulateConnIdVal(zeek::RecordVal& conn_id, zeek::RecordVal& ctx) override {
        // Base class populates conn_id fields (orig_h, orig_p, resp_h, resp_p)
        zeek::IPBasedConnKey::DoPopulateConnIdVal(conn_id, ctx);

        if ( conn_id.GetType() != id::conn_id )
            return;

	ctx.Assign(GetFlowIDOffset(), static_cast<zeek_uint_t>(key.flow_id));
    }

    void DoInit(const Packet& pkt) override {
        key.flow_id = static_cast<const FIDPacket*>(&pkt)->flow_id;
    }

    static int GetFlowIDOffset() {
        static const auto& conn_id_ctx = zeek::id::find_type<zeek::RecordType>("conn_id_ctx");
        static int flow_id_offset = conn_id_ctx->FieldOffset("flow_id");
        return flow_id_offset;
    }

private:
    friend class Factory;

    struct {
        struct detail::PackedConnTuple tuple;
        uint32_t flow_id;
    } __attribute__((packed, aligned)) key; // packed and aligned due to usage for hashing
};

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<FlowIDConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    if ( v.GetType() != id::conn_id )
        return zeek::unexpected<std::string>{"unexpected value type"};

    auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);
    if ( ! ck.has_value() )
        return ck;

    int flow_id_offset = FlowIDConnKey::GetFlowIDOffset();
    static int ctx_offset = id::conn_id->FieldOffset("ctx");

    auto* k = static_cast<FlowIDConnKey*>(ck.value().get());
    auto* ctx = v.AsRecordVal()->GetFieldAs<zeek::RecordVal>(ctx_offset);

    if ( flow_id_offset < 0 )
        return zeek::unexpected<std::string>{"missing flow_id field"};

    if ( ctx->HasField(flow_id_offset) )
        k->key.flow_id = ctx->GetFieldAs<zeek::CountVal>(flow_id_offset);

    return ck;
}

} // namespace zeek::plugin::Corelight_PcapFIDSource
