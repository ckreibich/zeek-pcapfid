#include "zeek/iosource/Component.h"

#include "config.h"
#include "Plugin.h"
#include "Source.h"

namespace zeek::plugin::Corelight_PcapFIDSource { Plugin plugin; }

using namespace zeek::plugin::Corelight_PcapFIDSource;

zeek::plugin::Configuration Plugin::Configure()
	{
        AddComponent(new zeek::iosource::PktSrcComponent("PcapFIDReader", "pcapfid", iosource::PktSrcComponent::BOTH,
							 PcapFIDSource::Instantiate,
							 {0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1}));
	zeek::plugin::Configuration config;
	config.name = "Corelight::PcapFIDSource";
	config.description = "Dummy implementation of a Packet-deriving packet source";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
