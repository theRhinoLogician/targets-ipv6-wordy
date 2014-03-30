local stdnse = require "stdnse"
local target = require "target"
local tab = require "tab"

description = [[
Generates all the possible IPv6 addresses given a wordlist and the position of
the 16-bit segments to "wordify". These addresses are then piped to Nmap if the
'newtargets' argument is used.
]]

---
--@usage
-- nmap -6 <base IPv6 address> --script targets-ipv6-wordy.nse --script-args 'newtargets,wordlist=<filename>,segments="<n>"'
-- @args wordlist    The filename of a hexadecimal-based wordlist (required).
-- @args segments    The position of the 16-bit segment(s) of an IPv6 address to swap for a word (required).
--                   These numbers should be separated by commas.
--                   Example:
--                   Given the address 0000:0000:0000:0000:0000:0000:0000:0000,
--                   the segments are    1    2    3    4    5    6    7    8.
--                   If the selected segments are 7 and 8, then segments="7,8".
--
-- NOTE: For this script to work, the target's IPv6 address must be given with all its 32 nibbles and their respective colons.


author = "Everardo Padilla Saca"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

prerule = function()
  if(not((nmap.address_family() == "inet6"))) then
    return false
  end
  print("FIRST")
end

local function format_output(results)
  local output = tab.new()
  if not target.ALLOW_NEW_TARGETS then
    output[#output + 1] = "Use --script-args=newtargets to add the results as targets"
  else
    print("ADD")
  end
  return stdnse.format_output(true, output)
end

function hostrule(host)
  print(host.ip)
  return 1 == 1
end


action = function(host)
  print("SECOND")
  local wordlist = stdnse.get_script_args("wordlist")
  local wordy_segments = stdnse.get_script_args("segments")
  local candidate_addresses = {}

  if target.ALLOW_NEW_TARGETS == true then
    for _, v in pairs(all_addresses) do
      if v:match(':') then
        target.add(v)
      end
    end
  end

  return format_output(candidate_addresses)
end
