local stdnse = require "stdnse"
local target = require "target"

description = [[
Generates all the possible IPv6 addresses given a wordlist and the position of
the 16-bit segments of a full 32-nibble IPv6 address to "wordify". As soon as
address is generated it is added to the target queue.
]]

---
--@usage
-- nmap -6 --script targets-ipv6-wordy.nse --script-args 'newtargets,targets-ipv6-wordy.wordlist=<filename>,targets-ipv6-wordy.segments="<n1,n2...>",targets-ipv6-wordy.base-address="<full 32-nibble IPv6 address>"'
-- @args wordlist        The filename of a hexadecimal-based wordlist (required).
-- @args segments        The position of the 16-bit segment(s) of an IPv6 address to swap for a word (required).
--                       These numbers should be separated by commas.
--                       Example:
--                       Given the address 0000:0000:0000:0000:0000:0000:0000:0001,
--                       the segments are    1    2    3    4    5    6    7    8.
--                       If the selected segments are 7 and 8, then segments="7,8".
-- @args base-address    The full 32-nibble IPv6 address to start from (required).
--
-- NOTE: For this script to work, the target's IPv6 address must be given with all its 32 nibbles and their respective colons.
--
-- Acknowledgements: 
--   Script created as part of the research conducted in Tec de Monterrey, Campus 
--   Monterrey, Mexico. This script's idea was influenced by Raul Fuentes Samaniego's
--   work (https://code.google.com/p/itsis-mx/).
--

author = "Everardo Padilla Saca"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

--- Load the wordlist into a table.
-- @param wordlist_filename    Filename of the wordlist.
-- @return words_talbe         Table containing the words.
local function load_words_from_file(wordlist_filename)
  words_table = {}
  for word in io.lines(wordlist_filename) do
    words_table[#words_table + 1] = word
  end
  return words_table
end

--- Create a shallow copy of a given array.
-- @param original    Array to copy.
-- @return copy       Resulting copy.
local function get_shallow_copy(original)
  local copy = {}
  for k, v in pairs(original) do
    copy[k] = v
  end
  return copy
end

--- Split a full 32-nibble IPv6 address into an array of 8 items, each one
-- having 4 nibbles.
-- @param target_ip_address_str   32-nibble target IPv6 address.
-- @return target_ip_address_arr  Array representation of that IPv6 address.
local function split_ipv6_address(target_ip_address_str)
  -- Append an extra colon to the IPv6 address for the sake of the following
  -- address-splitting algorithm.
  target_ip_address_str = target_ip_address_str .. ":"
  local target_ip_address_arr = {}
  local nibbles = ""
  for i = 1, string.len(target_ip_address_str) do
    if i % 5 == 0 then -- Found a colon.
      local index = (i / 5)
      target_ip_address_arr[index] = nibbles
      nibbles = ""
    else
      nibbles = nibbles .. string.sub(target_ip_address_str, i, i)
    end
  end
  return target_ip_address_arr
end

--- Generates all the possible addresses with the words in 'wordlist_filename'
-- After an address has been generated, add it to Nmap's scanning queue.
-- @param wordlist_filename        File name of the wordlist.
-- @param segments                 Chosen IPv6 4-nibble segments to "wordify".
-- @param target_ip_address_str    IPv6 address that will act as a base for generating new ones.
local function process_candidate_addresses(wordlist_filename, segments, target_ip_address_str)
  -- Get an array with the IPv6 nibbles.
  local target_ip_address_arr = split_ipv6_address(target_ip_address_str)

  -- The segment numbers are stored in an array for easy access.
  local segment_counter = 1
  local segment_numbers_arr = {}
  for segment_number in string.gmatch(segments, "%d+") do
    segment_numbers_arr[segment_counter] = tonumber(segment_number)
    segment_counter = segment_counter + 1
  end

  local words_table = load_words_from_file(wordlist_filename)
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
    end
    -- Add the generated address to the Nmap queue.
    target.add(table.concat(candidate_ip_address_arr, ":"))
    print(table.concat(candidate_ip_address_arr, ":"))
  end
end

function prerule()
  local wordlist_filename = stdnse.get_script_args(SCRIPT_NAME .. ".wordlist")
  local segments = stdnse.get_script_args(SCRIPT_NAME .. ".segments")
  local base_address = stdnse.get_script_args(SCRIPT_NAME .. ".base-address")
  if wordlist_filename == nil or segments == nil or base_address == nil or target.ALLOW_NEW_TARGETS == false then 
    return false
  end
  process_candidate_addresses(wordlist_filename, segments, base_address)
end

function hostrule(host)
  return true
end

function action()
end
