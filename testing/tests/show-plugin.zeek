# @TEST-EXEC: zeek -NN Corelight::PcapFIDSource |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
