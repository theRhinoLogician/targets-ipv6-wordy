targets-ipv6-wordy
====================

NSE script that generates addresses to be scanned, based on a list of hex-based words (eg. c0de, beef, cafe, aced). The address-generation algorithm works like this:


Words domain (n): ```{c0de, beef, cafe, aced}```


Base IP address: ```fe80:0000:0000:0000:0000:0000:0000:0000``` (note how all of the 32 characters have to be specified, meaning that ```::``` cannot be used because of the parsing process).


Chosen segments (m): ```7,8```


The amount of generated addresses is: ```n^m = 4^2 = 16```
Generated addresses:
```
fe80:0000:0000:0000:0000:0000:beef:beef
fe80:0000:0000:0000:0000:0000:cafe:beef
fe80:0000:0000:0000:0000:0000:aced:beef
fe80:0000:0000:0000:0000:0000:c0de:beef
fe80:0000:0000:0000:0000:0000:beef:cafe
fe80:0000:0000:0000:0000:0000:cafe:cafe
fe80:0000:0000:0000:0000:0000:aced:cafe
fe80:0000:0000:0000:0000:0000:c0de:cafe
fe80:0000:0000:0000:0000:0000:beef:aced
fe80:0000:0000:0000:0000:0000:cafe:aced
fe80:0000:0000:0000:0000:0000:aced:aced
fe80:0000:0000:0000:0000:0000:c0de:aced
fe80:0000:0000:0000:0000:0000:beef:c0de
fe80:0000:0000:0000:0000:0000:cafe:c0de
fe80:0000:0000:0000:0000:0000:aced:c0de
fe80:0000:0000:0000:0000:0000:c0de:c0de
```

For a 32-nibble IPv6 address, the script will look at the selected segments (1 or more of the 8 4-nibble segments that make an IPv6 address) and will change their original values with the words from the wordlist. The resulting IPv6 addresses will be added to nmap's target list. The command used to generate the previous addresses was:

```
$ nmap -6 --script targets-ipv6-wordy.nse --script-args 
  'newtargets,
  targets-ipv6-wordy.wordlist=words.txt,
  targets-ipv6-wordy.segments="7,8",
  targets-ipv6-wordy.base-address="fe80:0000:0000:0000:0000:0000:0000:0000"'
```

And the contents of ```words.txt``` was:
```
c0de
beef
cafe
aced
```
