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

author = "Everardo Padilla Saca"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}
