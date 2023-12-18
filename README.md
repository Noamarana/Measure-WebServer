# Measure-WebServer
/*------------------------------------------------------- Description ----------------------------------------------------------*/
This project, developed by Michael Burton and I, is a comprehensive tool for analyzing network traffic, specifically focusing 
on measuring and characterizing the latency of web servers. Utilizing Python and the Scapy library, this tool processes PCAP 
files to extract latency information and computes various statistical measures along with the Kullback-Leibler divergence for 
detailed network analysis.                                                                                                       
/*-----------------------------------------------------------------------------------------------------------------------------*/


/*------------------------------------------------------- Features ----------------------------------------------------------*/
Traffic Analysis: Analyzes network packets, distinguishing between TCP and UDP packets, and calculates the number of each type.
Latency Measurement: Extracts latency data for specific web server IPs and ports from network traffic.
Statistical Calculations: Computes average latency, percentile distributions of latencies, and other relevant statistics.
Kullback-Leibler Divergence Computation: Calculates the divergence between modeled and measured distributions of latency, 
providing insight into the consistency of network traffic.                                                                      
/*-----------------------------------------------------------------------------------------------------------------------------*/

/*------------------------------------------------------- How to Use ----------------------------------------------------------*/
Setup: Install Python and Scapy.
Running the Tool: Use the command python3 measure-webserver.py <input-file> <server-ip> <server-port> to initiate the analysis.
Interpreting Results: The tool outputs average latency, percentile values, and the Kullback-Leibler divergence for the analyzed 
traffic.
/*-----------------------------------------------------------------------------------------------------------------------------*/


