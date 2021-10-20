-- lua dissector for Simplemux

-- FIXME: only valid for the first header. It does NOT yet decode the second and
--subsequent headers

local simplemux = Proto("simplemux", "Simplemux packet/frame multiplexer");

-- declare the fields of the header
local f_SPB = ProtoField.uint8("simplemux.SPB", "SPB (Single Protocol Bit)", base.DEC)
local f_LXT = ProtoField.uint8("simplemux.LXT", "LXT (Length Extension)", base.DEC)
local f_LEN = ProtoField.uint16("simplemux.LEN", "LEN (Payload length)", base.DEC)

-- declare the value strings for the field 'Protocol'
local protocol_types = { [4] = "IPv4",
			 [143] = "Ethernet",
			 [142] = "ROHC" }

-- declare the field 'protocol type'
local protocol_type = ProtoField.uint8("simplemux.Protocol", "Protocol", base.DEC, protocol_types)

-- define the field structure of the Simplemux header
simplemux.fields = { f_SPB, f_LXT, f_LEN, protocol_type }

local data_dis = Dissector.get("data")

-- dissector function
function simplemux.dissector(buf, pkt, tree)
	-- put a name in the "protocol" column
	pkt.cols['protocol'] = "Simplemux"

	-- variable to store the offset: positions I have advanced
	local offset = 0

	-- first byte
	-- this is a way to get the most significant bit
	SPB = ( buf(0,1):uint() - ( buf(0,1):uint() % 128 ) ) / 128

	-- this is a way to get the second bit
	local value = buf(0,1):uint()

	-- remove the most significant bit
	if SPB == 1 then
		value = value - 128
	end
	LXT = ( value - (value % 64 ) ) / 64

	-- check if the length has 1 or 2 bytes (depending on LXT, second bit)
	if LXT == 0 then
		-- create the Simplemux protocol tree item
		-- the second argument of 'buf' means the number of bytes that are considered
		--a part of simplemux
		local subtree = tree:add(simplemux, buf(offset,2))

        	-- first byte (including SPB, LXT and LEN)
        	subtree:add(f_SPB, SPB)
		subtree:add(f_LXT, LXT)

		LEN = buf(offset,1):uint() % 64
		subtree:add(f_LEN, LEN)

		offset = offset + 1

		-- second byte: Protocol field
		Protocol = buf(offset,1):uint()
		subtree:add(protocol_type, Protocol)

		offset = offset + 1
	else
                -- create the Simplemux protocol tree item
                -- the second argument of 'buf' means the number of bytes that are considered
                --a part of simplemux
                local subtree = tree:add(simplemux, buf(offset,3))

		-- first byte (including SPB, LXT and part of LEN)
        	subtree:add(f_SPB, SPB)
        	subtree:add(f_LXT, LXT)

		-- seccond byte (including LXT and the rest of LEN)

		-- the length is between the first and the second bytes
		-- 6 bits come from the first byte (I remove the two most significant ones)
		-- 7 bits come from the second byte (I remove the most significant one)
                LEN = ((buf(offset,1):uint() % 64 ) * 128 )+ (buf(offset + 1,1):uint() % 128)
                subtree:add(f_LEN, LEN)

                offset = offset + 2

		-- third byte: Protocol
		Protocol = buf(offset,1):uint()
                subtree:add(protocol_type, Protocol)

		offset = offset + 1
	end

	-- dissect the next content

	-- if Protocol is 4, what comes next is an IP packet
	if Protocol == 4 then
		Dissector.get("ip"):call(buf(offset):tvb(), pkt, tree)
	end
	-- if Protocol is 143, there is an Eth frame inside
	if Protocol == 143 then
                Dissector.get("eth_withoutfcs"):call(buf(offset):tvb(), pkt, tree)
	end
	-- if Protocol is 142, there is a ROHC compressed packet inside
        if Protocol == 142 then
                Dissector.get("rohc"):call(buf(offset):tvb(), pkt, tree)
	end
end

-- load the UDP port table
local udp_encap_table = DissectorTable.get("udp.port")
local tcp_encap_table = DissectorTable.get("tcp.port")
local ip_encap_table = DissectorTable.get("ip.proto")

-- register the protocol to port 55555
udp_encap_table:add(55555, simplemux)
tcp_encap_table:add(55555, simplemux)
-- register IANA protocol 253 as Simplemux
ip_encap_table:add(253, simplemux)
