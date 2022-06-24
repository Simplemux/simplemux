-- lua dissector for Simplemux Blast mode

-- Pending: get the length from the previous header, instead of getting it from the length
-- of the buffer. This would avoid problems with e.g. PRP (it is a trailer at the end of the frame)

local debug = 0 -- set this to 1 if you want debug information

local simplemuxblast = Proto("simplemuxblast", "Simplemux packet/frame multiplexer, Blast version");


-- declare the value strings for the field 'Protocol'
local protocol_types = {[4] = "IPv4",
                        [143] = "Ethernet",
                        [142] = "ROHC" }


-- declare the field 'protocol type'
local protocol_type = ProtoField.uint8("simplemuxblast.Protocol", "Protocol", base.DEC, protocol_types)

-- define the field structure of the Simplemux header
simplemuxblast.fields = { protocol_type }

-- declare the field 'length'
simplemuxblast.fields.length = ProtoField.uint16("simplemuxblast.Length", "Length", base.DEC)

-- declare the field 'identifier'
simplemuxblast.fields.identifier = ProtoField.uint16("simplemuxblast.Identifier", "Identifier", base.DEC)

-- define the field 'ack'
simplemuxblast.fields.ack = ProtoField.uint8("simplemuxblast.ack","ack", base.DEC)

-- define this in order to show the bytes of the Simplemux payload
--simplemuxblast.fields.bytes = ProtoField.bytes("simplemuxblast.bytes", "Simplemux payload")


local data_dis = Dissector.get("data")

-- dissector function
function simplemuxblast.dissector(buf, pkt, tree)

  -- variable to store the offset: positions I have advanced
  local offset = 0
  local packetNumber = 0
  
  while (offset < buf:len()) do
  
    -- the simplemuxblast separator is 6 bytes long:
    --  length: 2 bytes
    --  protocol: 1 byte
    --  identifier: 2 bytes
    --  ack: 1 byte

    -- create the Simplemux protocol tree item
    -- the second argument of 'buf' means the number of bytes that are considered
    --a part of simplemuxblast
    local subtree = tree:add(simplemuxblast, buf(offset,6))
       
    -- length subtree: 2 bytes
    length = (buf(offset,1):uint() * 256 ) + buf(offset + 1,1):uint()
    subtree:add(simplemuxblast.fields.length, buf(offset,2))
    
    offset = offset + 2


    -- third byte: 'Protocol' field
    Protocol = buf(offset,1):uint()
    subtree:add(protocol_type, buf(offset,1))
  
    -- add the Protocol length to the offset
    offset = offset + 1
    

    -- fourth and fifth bytes: 'Identifier'
    identifier = (buf(offset,1):uint() * 256 ) + buf(offset + 1,1):uint()
    subtree:add(simplemuxblast.fields.identifier, buf(offset,2))
    
    offset = offset + 2


    -- sixth byte: 'ACK' field
    ack = buf(offset,1):uint()
    subtree:add(simplemuxblast.fields.ack, buf(offset,1))
  
    -- add the Protocol length to the offset
    offset = offset + 1


    -- add the content
    --simplemux_payload = buf(offset,length) 
    --subtree:add(simplemuxblast.fields.bytes, simplemux_payload)

    -- if this is not a Simplemux ACK, show the payload
    if ack == 0 then
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

    offset = offset + length

    
    packetNumber = packetNumber + 1

  end -- end while

end -- end of function simplemuxblast.dissector()

-- load the UDP port table
local udp_encap_table = DissectorTable.get("udp.port")
local tcp_encap_table = DissectorTable.get("tcp.port")
local ip_encap_table = DissectorTable.get("ip.proto")

-- register the protocol to port 55558
-- this is needed in Transport mode
-- UDP can be used with simplemuxblast
udp_encap_table:add(55558, simplemuxblast)
tcp_encap_table:add(55558, simplemuxblast)


-- register IANA protocol 252 as Simplemux blast
-- this is needed in Network mode
ip_encap_table:add(252, simplemuxblast)
