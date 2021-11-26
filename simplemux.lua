-- lua dissector for Simplemux

-- Pending: get the length from the previous header, instead of getting it from the length
-- of the buffer

local debug = 0 -- set this to 1 if you want debug information

local simplemux = Proto("simplemux", "Simplemux packet/frame multiplexer");

-- declare the fields of the header
local f_SPB = ProtoField.uint8("simplemux.SPB", "SPB (Single Protocol Bit)", base.DEC)
local f_LXT = ProtoField.uint8("simplemux.LXT", "LXT (Length Extension)", base.DEC)
local f_LEN = ProtoField.uint16("simplemux.LEN", "LEN (Payload length)", base.DEC)


-- declare the value strings for the field 'Protocol'
local protocol_types = {[4] = "IPv4",
                        [143] = "Ethernet",
                        [142] = "ROHC" }

-- declare the field 'protocol type'
local protocol_type = ProtoField.uint8("simplemux.Protocol", "Protocol", base.DEC, protocol_types)

-- define the field structure of the Simplemux header
simplemux.fields = { f_SPB, f_LXT, f_LEN, protocol_type }

-- define this in order to show the bytes of the Simplemux payload
simplemux.fields.bytes = ProtoField.bytes("simplemux.bytes", "Simplemux payload")


-- experiment based on https://stackoverflow.com/questions/51248914/how-to-handle-bit-fields-in-wireshark-lua-dissector
-- this prints '1... ....' or '0... ....' depending on the value of the first bit
simplemux.fields.first_header_first_bit = ProtoField.uint8("Single_Protocol_Bit", "Single Protocol Bit", base.DEC, null, 0x80)

-- this prints '.1.. .....' or '.0.. ....' depending on the value of the second bit
simplemux.fields.first_header_second_bit = ProtoField.uint8("Length_Extenxsion_First_Header", "Length extension", base.DEC, null, 0x40)

-- this prints '1... ....' or '0... ....' depending on the value of the first bit
simplemux.fields.non_first_header_first_bit = ProtoField.uint8("Length_Extension_non-First_header", "Length extension", base.DEC, null, 0x80)

-- this prints '..101010', i.e. the value of the six less-significant bits
simplemux.fields.first_header_third_to_eighth_bits = ProtoField.uint8("Length_6bits", "Length", base.DEC, null, 0x3F)

-- this prints '.0101010', i.e. the value of the seven less-significant bits
simplemux.fields.non_first_header_second_to_eighth_bits = ProtoField.uint8("Length_7bits", "Length", base.DEC, null, 0x7F)

-- this prints '..101010 10101010', i.e. the value of the seven less-significant bits
simplemux.fields.first_header_third_to_sixteenth_bits = ProtoField.uint16("Length_14bits", "Length", base.DEC, null, 0x3FFF)

-- this prints '.0101010 10101010', i.e. the value of the seven less-significant bits
simplemux.fields.non_first_header_second_to_sixteenth_bits = ProtoField.uint16("Length_15bits", "Length", base.DEC, null, 0x7FFF)


local data_dis = Dissector.get("data")

-- dissector function
function simplemux.dissector(buf, pkt, tree)

  if (debug == 1 ) then
    print()
  end
  
  -- I check if there is a single protocol, i.e. the Protocol field is only present
  -- in the first simplemux separator
  local singleProtocol = 0
  
  -- first byte of the first simplemux separator
  --   Most significant bit: SPB
  --   second bit: LXT
  --   six bits: part of the LENGTH
  
  -- this is a way to get the most significant bit
  singleProtocol = ( buf(0,1):uint() - ( buf(0,1):uint() % 128 ) ) / 128

  -- experiment
  --local single_range = buf(0,1)
  --local single_ = single:uint()
  --subtree:add(single, single_range, single_)

  -- variable to store the offset: positions I have advanced
  local offset = 0
  local packetNumber = 0 
  
  while (offset < buf:len()) do
  
    -- ************************ first separator ********************
    if (packetNumber == 0) then
      -- first byte of the first simplemux separator
      --   Most significant bit: SPB
      --   second bit: LXT
      --   six bits: part of the LENGTH
      
      -- this is a way to get the most significant bit
      SPB = ( buf(offset,1):uint() - ( buf(offset,1):uint() % 128 ) ) / 128
              
      -- this is a way to get the second bit
      local value = buf(0,1):uint()
      -- remove the most significant bit
      if SPB == 1 then
        value = value - 128
      end
      LXT = ( value - (value % 64 ) ) / 64
      
      -- check if the length has 1 or 2 bytes (depending on LXT, second bit)
      if LXT == 0 then
        -- the simplemux separator is 2 bytes long:
        --  first byte: SPB-LXT-LEN (6 bits)
        --  second byte: protocol

        -- create the Simplemux protocol tree item
        -- the second argument of 'buf' means the number of bytes that are considered
        --a part of simplemux
        local subtree = tree:add(simplemux, buf(offset,2))
           
        -- the length field is 6 bits long
        LEN = buf(offset,1):uint() % 64
        
        if (debug == 1 ) then
          print("   offset: " .. offset .. " LEN: " .. LEN)
          print("  packet " .. packetNumber .. "  the length field is 6 bits long")  
        end
        
        -- first byte (including SPB, LXT and LEN)
        -- subtree:add(f_SPB, SPB)
        -- subtree:add(f_LXT, LXT)
        -- subtree:add(f_LEN, LEN)

        -- add SPB
        subtree:add(simplemux.fields.first_header_first_bit, buf(offset,1))
        -- add LXT
        subtree:add(simplemux.fields.first_header_second_bit, buf(offset,1))
        -- add length
        subtree:add(simplemux.fields.first_header_third_to_eighth_bits, buf(offset,1))

        offset = offset + 1

        -- second byte: 'Protocol' field
        Protocol = buf(offset,1):uint()
        subtree:add(protocol_type, buf(offset,1))
      
        -- add the Protocol length to the offset
        offset = offset + 1
        
        -- add the content
        simplemux_payload = buf(offset,LEN) 
        subtree:add(simplemux.fields.bytes, simplemux_payload)

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

        offset = offset + LEN
        
      else -- LXT == 1
        -- the simplemux separator is 3 bytes long:
        --  first byte: SPB-LXT-LEN1
        --  second byte: LEN2
        --  third byte: protocol
        if (debug == 1 ) then
          print("  packet " .. packetNumber .. "  the length field is 14 bits long")
        end
        
        -- the length field is 14 bits long
        
        -- create the Simplemux protocol tree item
        -- the second argument of 'buf' means the number of bytes that are considered
        -- a part of simplemux
        local subtree = tree:add(simplemux, buf(offset,3))
    
        -- first byte (including SPB, LXT and part of LEN)
        -- subtree:add(f_SPB, SPB)
        -- subtree:add(f_LXT, LXT)
    
        -- second byte (including LXT and the rest of LEN)
    
        -- the length is between the first and the second bytes
        -- 6 bits come from the first byte (I remove the two most significant ones)
        -- 7 bits come from the second byte (I remove the most significant one)
        LEN = ((buf(offset,1):uint() % 64 ) * 128 )+ (buf(offset + 1,1):uint() % 128)
        if (debug == 1 ) then
          print("   offset: " .. offset .. " LEN: " .. LEN)
        end
        -- subtree:add(f_LEN, LEN)

        -- add SPB
        subtree:add(simplemux.fields.first_header_first_bit, buf(offset,1))
        -- add LXT
        subtree:add(simplemux.fields.first_header_second_bit, buf(offset,1))
        -- add Length
        subtree:add(simplemux.fields.first_header_third_to_sixteenth_bits, buf(offset,2))

 
        offset = offset + 2
      
        -- last byte: Protocol field
        Protocol = buf(offset,1):uint()
        subtree:add(protocol_type, buf(offset,1))
      
        offset = offset + 1        
        
        -- add the content
        simplemux_payload = buf(offset,LEN) 
        subtree:add(simplemux.fields.bytes, simplemux_payload)


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

        offset = offset + LEN
      end  
      
    else
      -- ************************ non-first separator ********************
      -- first byte of a non-first simplemux separator
      --   Most significant bit: LXT
      --   seven bits: part of the LENGTH
      
      -- this is a way to get the most significant bit
      LXT = ( buf(offset,1):uint() - ( buf(offset,1):uint() % 128 ) ) / 128

      -- check if the length has 1 or 2 bytes (depending on LXT)
      if LXT == 0 then
        -- the simplemux separator has this structure:
        --  first byte: LXT-LEN
        --  OPTIONAL: second byte: protocol
        
        -- the length field is 7 bits long
        LEN = buf(offset,1):uint() % 128
        
        if (debug == 1 ) then
          print("  packet " .. packetNumber .. "  the length field is 7 bits long")  
          print("   offset: " .. offset .. " LEN: " .. LEN)
        end

        if (singleProtocol == 0) then
          -- the simplemux separator DOES have a 'Protocol' field
          
          -- create the Simplemux protocol tree item
          -- the second argument of 'buf' means the number of bytes that are considered
          -- a part of simplemux
          local subtree = tree:add(simplemux, buf(offset,2))
      
          -- first byte (including LXT and LEN)
          -- subtree:add(f_LXT, LXT)
          -- subtree:add(f_LEN, LEN)

          -- add LXT
          subtree:add(simplemux.fields.non_first_header_first_bit, buf(offset,1))
          -- add length
          subtree:add(simplemux.fields.non_first_header_second_to_eighth_bits, buf(offset,1))

          offset = offset + 1
                
          -- last byte: 'Protocol' field
          Protocol = buf(offset,1):uint()
          subtree:add(protocol_type, buf(offset,1))
      
          -- add the Protocol length to the offset
          offset = offset + 1
          
          -- add the content
          simplemux_payload = buf(offset,LEN) 
          subtree:add(simplemux.fields.bytes, simplemux_payload)

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

          offset = offset + LEN
        else
          -- the simplemux separator does NOT have a 'Protocol' field
          
          -- create the Simplemux protocol tree item
          -- the second argument of 'buf' means the number of bytes that are considered
          -- a part of simplemux
          local subtree = tree:add(simplemux, buf(offset,1))
      
          -- first byte (including LXT and LEN)
          -- subtree:add(f_LXT, LXT)
          -- subtree:add(f_LEN, LEN)

          -- add LXT
          subtree:add(simplemux.fields.non_first_header_first_bit, buf(offset,1))
          -- add length
          subtree:add(simplemux.fields.non_first_header_second_to_eighth_bits, buf(offset,1))

          offset = offset + 1
          
          -- add the content
          simplemux_payload = buf(offset,LEN) 
          subtree:add(simplemux.fields.bytes, simplemux_payload)
          
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

          offset = offset + LEN  
        end  

      else -- LXT == 1
        -- the simplemux separator has this structure:
        --  first byte: LXT-LEN1
        --  second byte: LEN2
        --  OPTIONAL: second byte: protocol  
    
        if (debug == 1 ) then
          print("  packet " .. packetNumber .. "  the length field is 15 bits long")
        end
        -- the length field is 15 bits long
        
        -- second byte (including LXT and the rest of LEN)
    
        -- the length is between the first and the second bytes
        -- 6 bits come from the first byte (I remove the two most significant ones)
        -- 7 bits come from the second byte (I remove the most significant one)
        LEN = ((buf(offset,1):uint() % 64 ) * 128 )+ (buf(offset + 1,1):uint() % 128)
        if (debug == 1 ) then
          print("   offset: " .. offset .. " LEN: " .. LEN)
        end
      
        if (singleProtocol == 0) then
          -- the simplemux separator DOES have a 'Protocol' field
          
          -- create the Simplemux protocol tree item
          -- the second argument of 'buf' means the number of bytes that are considered
          -- a part of simplemux
          local subtree = tree:add(simplemux, buf(offset,3))
      
          -- first and second bytes (including LXT and LEN)
          -- subtree:add(f_LXT, LXT)
          -- subtree:add(f_LEN, LEN)

          -- add LXT
          subtree:add(simplemux.fields.non_first_header_first_bit, buf(offset,1))
          -- add length
          subtree:add(simplemux.fields.non_first_header_second_to_sixteenth_bits, buf(offset,1))

          offset = offset + 2
        
          -- last byte: 'Protocol' field
          Protocol = buf(offset,1):uint()
          subtree:add(protocol_type, buf(offset,1))
      
          -- add the Protocol length to the offset
          offset = offset + 1
          
          -- add the content
          simplemux_payload = buf(offset,LEN) 
          subtree:add(simplemux.fields.bytes, simplemux_payload)

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

          offset = offset + LEN
        else
          -- the simplemux separator does NOT have a 'Protocol' field
          
          -- create the Simplemux protocol tree item
          -- the second argument of 'buf' means the number of bytes that are considered
          -- a part of simplemux
          local subtree = tree:add(simplemux, buf(offset,2))
      
          -- first and second bytes (including LXT and LEN)
          -- subtree:add(f_LXT, LXT)
          -- subtree:add(f_LEN, LEN)

          -- add LXT
          subtree:add(simplemux.fields.non_first_header_first_bit, buf(offset,1))
          -- add length
          subtree:add(simplemux.fields.non_first_header_second_to_sixteenth_bits, buf(offset,1))

          offset = offset + 2
          
          -- add the content
          simplemux_payload = buf(offset,LEN) 
          subtree:add(simplemux.fields.bytes, simplemux_payload)
          
          offset = offset + LEN  
        end
      end
    end
    
    packetNumber = packetNumber + 1
    if (debug == 1 ) then
      print ("   total bufLen: " .. buf:len() .. ". LEN: " .. LEN .. ". offset: " .. offset .. ". packets: " .. packetNumber)  
    end    

  end -- end while    

end -- end of function simplemux.dissector()

-- load the UDP port table
local udp_encap_table = DissectorTable.get("udp.port")
local tcp_encap_table = DissectorTable.get("tcp.port")
local ip_encap_table = DissectorTable.get("ip.proto")

-- register the protocol to port 55555
-- this is needed in Transport mode
udp_encap_table:add(55555, simplemux)
tcp_encap_table:add(55555, simplemux)

-- register IANA protocol 253 as Simplemux
-- this is needed in Network mode
ip_encap_table:add(253, simplemux)
