# ARP Request

This is a project where I send an **ARP request** for some IP address with raw sockets.

## How to use

In this program, you must write in the terminal your network interface and the IP address from which you want to know your MAC address.

| Target MAC | Source MAC | ... | Source MAC | Source IP | Target  MAC | Target IP
|--|--|--|--|--|--|--|
| `FF:FF:FF:FF:FF:FF` | `A1:B2:C3:D4:E5:F6` |  | `A1:B2:C3:D4:E5:F6` | `192.168.1.1` | `00:00:00:00:00:00` | `192.168.1.1`
