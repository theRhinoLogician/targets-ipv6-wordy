local math = require "math"

local wordy_segments = "1,8"
local target_ip_address_arr = {}
local target_ip_address_str = "2001:0db8:0000:0000:0000:0000:0000:0001"
local file = 'nselib/data/hex-wordy-en.lst'

-- Append an extra colon to the IPv6 address for the sake of the following
-- address-splitting algorithm.
target_ip_address_str = target_ip_address_str .. ":"

-- Gets to hold each 4 nibbles for each one of the 8 segments.
local nibbles = ""

for i = 1, string.len(target_ip_address_str) do
  -- Every fifth character in our modified IPv6 address should be a colon.
  if i % 5 == 0 then
    -- For any well-formed IPv6 address, index goes from 1 to 8.
    local index = (i / 5)
    -- Save the segments in an array for easy access.
    target_ip_address_arr[index] = nibbles
    -- Restart the nibbles for the upcoming segment.
    nibbles = ""
  else
    -- Append the current character to the nibbles string.
    nibbles = nibbles ..  string.sub(target_ip_address_str, i, i)
  end
end

-- Gets which segments should be wordy.
for segment_number in string.gmatch(wordy_segments, "%d+") do
  -- Cast to int.
  segment_number = segment_number + 0
  for word in io.lines(file) do
    target_ip_address_arr[segment_number] = word
    local entry = table.concat(target_ip_address_arr, ":")
    print(entry)
  end
end


local function generate_candidate_addresses()
  print(123)
end
