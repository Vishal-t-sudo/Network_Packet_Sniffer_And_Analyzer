# Packet Sniffer and Analyzer Tool

## About

A versatile packet sniffer and analyzer tool written in C. This tool provides a user-friendly interface for capturing, dissecting, and analyzing network packets in real-time. Whether you're a network administrator, security analyst, or developer, this tool offers valuable insights into network traffic.

## Usage

1. **Install Dependencies**:
   - Ensure you have the necessary dependencies installed:
     - [libpcap](https://www.tcpdump.org/) (Linux)
     - [Npcap](https://nmap.org/npcap/) (Windows)
     - [gcc](https://gcc.gnu.org/) (for compiling C code)
   
2. **Clone the Repository**:
```
git clone https://github.com/Vishal-t-sudo/Network_Packet_Sniffer_And_Analyzer.git
```


3. **Navigate to the Repository**:
```
cd Network_Packet_Sniffer_And_Analyzer
```


4. **Build**:
```
gcc -o capture Packetsniffer and Analyzer.c -lpcap
```

5. **Run**:
```
sudo ./capture
```

## Features

- Capture packets from network interfaces.
- Analyze Ethernet, IP, TCP, and UDP protocols.
- Display packet information such as source and destination addresses, protocol, length, and more.
- Customizable packet analysis logic.


