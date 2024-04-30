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
gcc -o capture Packetsniffer_and_Analyzer.c -lpcap
```

5. **Run**:
```
sudo ./capture [Network interface to capture packets]
```
Eg: sudo ./capture enp0s3  [For Ubuntu / Debian]

## Capturing and Analysis of Network Traffic

- Once you have completed building the "capture" executable follow the below steps to start the packet capture and analysis:
1. Run the executable by typing "./capture" in your terminal and press Enter.
2. The program will start capturing packets from the specified network interface (e.g., eth0, wlan0).
3. It will continuously print details about each captured packet to the terminal, including packet length, timestamp, size, and initial packet data bytes.
4. Additionally, Ethernet, IP, TCP, and UDP headers (if present) will be printed for each packet.
5. To stop capturing packets and exit the program, use Ctrl + C or any other method to terminate the execution.
6. Analyze the output printed in the terminal to gain insights into the network traffic, such as MAC addresses, IP addresses, ports, and packet sizes.

## Features

- Capture packets from network interfaces.
- Analyze Ethernet, IP, TCP, and UDP protocols.
- Display packet information such as source and destination addresses, protocol, length, and more.
- Customizable packet analysis logic.


