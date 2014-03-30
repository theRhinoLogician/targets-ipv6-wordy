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
