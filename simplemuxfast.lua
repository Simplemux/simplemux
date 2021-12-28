-- lua dissector for Simplemux

-- Pending: get the length from the previous header, instead of getting it from the length
-- of the buffer. This would avoid problems with e.g. PRP (it is a trailer at the end of the frame)

local debug = 0 -- set this to 1 if you want debug information

local simplemuxfast = Proto("simplemuxfast", "Simplemux packet/frame multiplexer, Fast version");


-- declare the value strings for the field 'Protocol'
local protocol_types = {[4] = "IPv4",
                        [143] = "Ethernet",
                        [142] = "ROHC" }


-- declare the field 'protocol type'
local protocol_type = ProtoField.uint8("simplemuxfast.Protocol", "Protocol", base.DEC, protocol_types)

-- define the field structure of the Simplemux header
simplemuxfast.fields = { protocol_type }

-- declare the field 'length'
simplemuxfast.fields.length = ProtoField.uint16("simplemuxfast.Length", "Length", base.DEC)

-- define this in order to show the bytes of the Simplemux payload
simplemuxfast.fields.bytes = ProtoField.bytes("simplemuxfast.bytes", "Simplemux payload")


local data_dis = Dissector.get("data")

-- dissector function
function simplemuxfast.dissector(buf, pkt, tree)

  -- variable to store the offset: positions I have advanced
  local offset = 0
  local packetNumber = 0
  
  while (offset < buf:len()) do
  
    -- the simplemux separator is 3 bytes long:
    --  length: 2 bytes
    --  protocol: 1 byte

    -- create the Simplemux protocol tree item
    -- the second argument of 'buf' means the number of bytes that are considered
    --a part of simplemuxfast
    local subtree = tree:add(simplemuxfast, buf(offset,3))
       
    -- length subtree: 2 bytes
    length = (buf(offset,1):uint() * 256 ) + buf(offset + 1,1):uint()
    subtree:add(simplemuxfast.fields.length, buf(offset,2))
    
    offset = offset + 2

    -- third byte: 'Protocol' field
    Protocol = buf(offset,1):uint()
    subtree:add(protocol_type, buf(offset,1))
  
    -- add the Protocol length to the offset
    offset = offset + 1
    
    -- add the content
    simplemux_payload = buf(offset,length) 
    subtree:add(simplemuxfast.fields.bytes, simplemux_payload)

    if Protocol == 4 then
      Dissector.get("ip"):call(buf(offset):tvb(), pkt, subtree)
    end
    -- if Protocol is 143, there is an Eth frame inside
    if Protocol == 143 then
      Dissector.get("eth_withoutfcs"):call(buf(offset):tvb(), pkt, subtree)
    end
    -- if Protocol is 142, there is a ROHC compressed packet inside
    if Protocol == 142 then
      Dissector.get("rohc"):call(buf(offset):tvb(), pkt, subtree)
    end

    offset = offset + length

    
    packetNumber = packetNumber + 1

  end -- end while

end -- end of function simplemuxfast.dissector()

-- load the UDP port table
local udp_encap_table = DissectorTable.get("udp.port")
local tcp_encap_table = DissectorTable.get("tcp.port")
local ip_encap_table = DissectorTable.get("ip.proto")

-- register the protocol to port 55555 and 55557
-- this is needed in Transport mode
-- UDP can be used with simplemux and simplemuxFast
-- TCP can oly be used with simplemuxFast
udp_encap_table:add(55557, simplemuxfast)
tcp_encap_table:add(55557, simplemuxfast)


-- register IANA protocol 254 as Simplemux fast
-- this is needed in Network mode
ip_encap_table:add(254, simplemuxfast)
