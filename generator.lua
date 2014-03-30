local math = require "math"

local wordy_segments = "1,2,3"
local target_ip_address_arr = {}
local target_ip_address_str = "2001:0db8:0000:0000:0000:0000:0000:0001"
local words_file = 'nselib/data/hex-wordy-en.lst'

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
    nibbles = nibbles .. string.sub(target_ip_address_str, i, i)
  end
end


local segment_quantity = 0
-- Gets which segments should be wordy.
for segment_number in string.gmatch(wordy_segments, "%d+") do
  -- Cast to int.
  segment_number = segment_number + 0
  segment_quantity = segment_quantity + 1
end

-- Loads the words file into a table.
local function load_words()
  words_table = {}
  for word in io.lines(words_file) do
    words_table[#words_table + 1] = word
  end
  return words_table
end

local words_table = load_words()
local word_change_triggers = {}
local word_current_count = {}
local total_candidate_addresses = math.pow(#words_table, segment_quantity);

-- A word-change trigger tells the generator when to change the word it's using.
for i = 0, #words_table do
  word_change_triggers[i] = math.pow(#words_table, i)
end

for i = 0, total_candidate_addresses-1 do
  for j = 0, segment_quantity-1 do
    if i % word_change_triggers[j] == 0 then
      if word_current_count[j] == nil then
        word_current_count[j] = 0
      end
      word_current_count[j] = word_current_count[j] + 1
    end
    print(words_table[(word_current_count[j] % #words_table)+1])
  end
  print('---')
end
