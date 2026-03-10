# PacketVision

Uses PyShark to display sent packets and their destinations/sources. Resolves IP's using dns if able to, and organizes using a pi chart. 
Flags suspicious events including: Port scans, DNS tunneling, ICMP floods, General high packet volume/rate, suspicious port traffic.

## Usage 

### Testing suspicious events

ICMP flood: 
```bash
sudo ping -i 0.01 -c 600 8.8.8.8
```
(Use in terminal to run program -> loopback interface monitoring needed to test)
```bash
sudo PV_INTERFACE=lo0 python3 packetvision.py
``` 
Port scan (nmap install needed): 
```bash
nmap -p 1-1000 127.0.0.1
``` 

Use in terminal to run program -> loopback interface monitoring needed to test)
```bash
sudo PV_INTERFACE=lo0 python3 packetvision.py
``` 
Suspicious port: 
```bash
nc 127.0.0.1 4444
``` 

DNS tunneling: 
```bash
dig aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com
``` 
