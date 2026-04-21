# Traffic Classification System using POX (SDN)

## Problem Statement
Classify network traffic based on protocol type (TCP, UDP, ICMP) using an SDN approach.
The POX controller monitors packets flowing through the network and identifies their protocol, demonstrating how SDN enables centralized traffic analysis.

---

## Topology
h1 (10.0.0.1) --- s1 --- h2 (10.0.0.2), h3 (10.0.0.3)
|
POX Controller

---

## SDN Logic
- Switch sends packets to POX controller (default behavior)
- Controller inspects packets using OpenFlow events
- Traffic is classified based on protocol:
- ICMP → Ping traffic
- TCP → Connection-based traffic
- UDP → Connectionless traffic
- Controller logs packet type in real-time

---

## Setup & Installation

### Requirements
- Ubuntu 22.04 (VM or WSL)
- Mininet
- Open vSwitch
- Python 3
- POX Controller

---

### Install Mininet
sudo apt install mininet -y
sudo apt install openvswitch-switch -y

---

### Install POX
cd ~
git clone https://github.com/noxrepo/pox.git
cd pox

---

## Running the Project

### Terminal 1 — Start POX Controller
cd ~/pox
./pox.py misc.traffic_classification

---

### Terminal 2 — Start Mininet
sudo mn -c
sudo mn --topo single,3 --controller remote

---

## Test Scenarios

### Scenario 1 — Basic Connectivity
mininet> pingall

Expected:
All hosts should communicate successfully (0% packet loss)

---

### Scenario 2 — ICMP Traffic (Ping)
mininet> h1 ping h2

Expected Output:
ICMP packets detected in controller logs

---

### Scenario 3 — TCP Traffic
mininet> iperf

Expected Output:
TCP traffic identified and logged

---

### Scenario 4 — UDP Traffic
mininet> h1 iperf -s -u &
mininet> h2 iperf -u -c h1

Expected Output:
UDP packets detected by controller

---

## Traffic Classification Output
The controller displays:
- ICMP Packet Detected
- TCP Packet Detected
- UDP Packet Detected

This confirms successful classification of traffic.

---

## Performance Observation
Using iperf:
- TCP provides reliable transmission
- UDP provides faster but unreliable transmission
- ICMP used for reachability testing

---

## Proof of Execution
- Ping results (ICMP classification)
- iperf results (TCP/UDP classification)
- Controller logs showing protocol detection

---

## Applications
- Network monitoring
- Traffic analysis
- Intrusion detection systems
- SDN-based traffic control

---

## Author
Akash Ramesh (PES1UG24AM212)

---

## Conclusion
This project demonstrates how SDN controllers like POX can be used to classify and monitor network traffic in real-time.
By integrating Mininet with POX, we can analyze protocol behavior and understand traffic patterns efficiently.

---

## References
Mininet: https://mininet.org
POX Controller: https://github.com/noxrepo/pox
OpenFlow Specification: https://opennetworking.org
