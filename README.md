targets-ipv6-wordy
====================

NSE script that looks for hosts with an IPv6 address containing known words


The address-generation algorithm works like this:
consider that the domain is {0, 1} and that the chosen segments are 3, the generated combinations would be:


```
111
011
101
001
110
010
100
000
```


For a 32-nibble IPv6 address, the script will look at the selected segments (1 or more of the 8 4-nibble segments) and will change their original values with the words from the wordlist. The resulting IPv6 addresses will then be piped to Nmap.


```
---
--@usage
-- nmap -6 <base IPv6 address> --script targets-ipv6-wordy.nse --script-args 'newtargets,targets-ipv6-wordy.wordlist=<filename>,targets-ipv6-wordy.segments="<n>",targets-ipv6-wordy.base-address="<IPv6 address>"'
-- @args wordlist The filename of a hexadecimal-based wordlist (required).
-- @args segments The position of the 16-bit segment(s) of an IPv6 address to swap for a word (required).
-- These numbers should be separated by commas.
-- Example:
-- Given the address 0000:0000:0000:0000:0000:0000:0000:0001,
-- the segments are 1 2 3 4 5 6 7 8.
-- If the selected segments are 7 and 8, then segments="7,8".
-- @args base-address The full 32-nibble IPv6 address to start from (required).
--
-- NOTE: For this script to work, the target's IPv6 address must be given with all its 32 nibbles and their respective colons.
--
--
--@output
--|_targets-ipv6-wordy: Found 42 responsive wordy hosts
--
--
-- Acknowledgements:
-- Script created as part of the research conducted in Tec de Monterrey, Campus
-- Monterrey, Mexico. This script's idea was influenced by Raul Fuentes Samaniego's
-- work (https://code.google.com/p/itsis-mx/).
--
```
