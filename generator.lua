local math = require "math"

local wordy_segments = "1,8"
local target_ip_address_arr = {}
local target_ip_address_str = "2001:0db8:0000:0000:0000:0000:0000:0001"
local words_file = 'nselib/data/hex-wordy-en.lst'

--- 
-- Append an extra colon to the IPv6 address for the sake of the following
-- address-splitting algorithm.
target_ip_address_str = target_ip_address_str .. ":"

--- 
-- Every fifth character in our modified IPv6 address should be a colon.
-- For any well-formed IPv6 address, index goes from 1 to 8.
-- Gets each 4 nibble segments and stores them in an array for easy access.
local nibbles = ""
for i = 1, string.len(target_ip_address_str) do
  if i % 5 == 0 then
    local index = (i / 5)
    target_ip_address_arr[index] = nibbles
    nibbles = ""
  else
    nibbles = nibbles .. string.sub(target_ip_address_str, i, i)
  end
end

--- 
-- Wordy segments are the 4 nibble groups that the user chose to make wordy.
-- The segment numbers are stored in an array for easy access.
local segment_counter = 1
local segment_numbers_arr = {}
for segment_number in string.gmatch(wordy_segments, "%d+") do
  segment_numbers_arr[segment_counter] = tonumber(segment_number)
  segment_counter = segment_counter + 1
end

-- Loads the wordlist into a table.
local function load_words()
  words_table = {}
  for word in io.lines(words_file) do
    words_table[#words_table + 1] = word
  end
  return words_table
end

-- Creates a shallow copy of a given table/array.
local function get_shallow_copy(original)
  local copy = {}
  for k, v in pairs(original) do
    copy[k] = v
  end
  return copy
end

local words_table = load_words()
local word_change_triggers = {}
local word_current_count = {}
local total_candidate_addresses = math.pow(#words_table, #segment_numbers_arr);

-- A word-change trigger tells the generator when to change the word it's using.
for i = 0, #words_table do
  word_change_triggers[i] = math.pow(#words_table, i)
end

-- Generate all candidate addresses.
for i = 0, total_candidate_addresses - 1 do
  local candidate_ip_address_arr = get_shallow_copy(target_ip_address_arr)
  for j = 0, #segment_numbers_arr - 1 do
    if i % word_change_triggers[j] == 0 then
      if word_current_count[j] == nil then
        word_current_count[j] = 0
      end
      word_current_count[j] = word_current_count[j] + 1
    end
    candidate_ip_address_arr[segment_numbers_arr[j + 1]] = words_table[(word_current_count[j] % #words_table + 1)]
    --print(words_table[(word_current_count[j] % #words_table + 1)])
  end
  print(table.concat(candidate_ip_address_arr, ":"))
end
