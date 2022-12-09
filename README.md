# gowhois
GOWHOIS, query multiple domains at once.

Based on https://github.com/likexian/whois.

Usage:
  -blind
        Print raw whois info even if an error during parsing occurs. (default true)
  -input string
        Domain/IP/AS to analyse
  -input-list string
        File containing a list of domain/IP/AS to analyse
  -parse
        Set to true if you want parsed results. (default true)
  -retry int
        Number of retries if fail. (default 5)
  -threads int
        Number of threads. (default 1)
