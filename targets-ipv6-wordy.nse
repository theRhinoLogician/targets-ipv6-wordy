local target = require "target"

description = [[
Given a hexadecimal-based wordlist, tries to find responsive hosts that contain 
one or more of those words in their IPv6 address.
]]

---
--@usage
-- nmap --script targets-ipv6-wordy --script-args wordlist=<filename> <target network>
-- @args wordlist The filename of a hexadecimal-based wordlist (required).
--@output
-- Found 42 wordy hosts.
-- nmap 192.168.1.254 --script /home/ever/github/targets-ipv6-wordy/targets-ipv6-wordy.nse --script-args 'newtargets'

author = "Everardo Padilla Saca"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

function hostrule(host)
  print(host.ip)
  return 1 == 1
end

function action(host)
  print(host.ip)
  print('wat')
  --local status, err = target.add("192.168.1.228")
end
