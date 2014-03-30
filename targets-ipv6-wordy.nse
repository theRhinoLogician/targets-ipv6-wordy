local stdnse = require "stdnse"
local target = require "target"

description = [[
Generates all the possible IPv6 addresses given a wordlist and the position of
the 16-bit segments to "wordify". These addresses are then piped to Nmap.
]]

---
--@usage
-- nmap -6 <base IPv6 address> --script targets-ipv6-wordy.nse --script-args 'newtargets,wordlist=<filename>,segments="<n>"'
-- @args wordlist    The filename of a hexadecimal-based wordlist (required).
-- @args segments    The position of the 16-bit segment of an IPv6 address to swap for a word (required).
--                   These numbers should be separated by commas.
--                   Example:
--                   Given the address 0000:0000:0000:0000:0000:0000:0000:0000,
--                   the segments are    1    2    3    4    5    6    7    8.
--                   If the selected segments are 7 and 8, then segments="7,8".


author = "Everardo Padilla Saca"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

function hostrule(host)
  print(host.ip)
  return 1 == 1
end

function action(host)
  local wordy_segments = stdnse.get_script_args(SCRIPT_NAME .. ".wordy-segments")
  print("-->"..wordy_segments)
end
