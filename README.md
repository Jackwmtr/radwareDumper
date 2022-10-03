# radwareDumper
script that gets a blocked IP data from Radware WAF and uploads it in an upstream DPRO
It also contains a ipv4 sorter module which is intended to take some IP's based on network summary data to squeese the list to DPRO limitations
Should be used in command line to refresh DPRO data on CRON basis.
DEPS:
requests, json
