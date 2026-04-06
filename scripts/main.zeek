module PcapFIDSource;

redef record conn_id_ctx += {
	flow_id: count &log &optional;
};

redef ConnKey::factory=ConnKey::CONNKEY_FLOW_ID_FIVETUPLE;
