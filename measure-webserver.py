from scapy.all import *
import sys
import time
import math

session_list= {}
def main():
    # Checks for the correct number of command-line arguments
    if len(sys.argv) != 4:
        print("Usage: python3 measure-webserver.py <input-file> <server-ip> <server-port>")
        sys.exit(1)

    input_file = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3])
    latencies = handle_pcap(input_file,server_ip,server_port)
    calculate_statistics(latencies)

    computing_kullbackLeibler_divergence(latencies)

# Reads a PCAP file and process it to extract latency information
def handle_pcap(input_file, server_ip, server_port):

    # make sure to load the HTTP layer
    load_layer("http")

    # example counters
    number_of_packets_total = 0
    number_of_tcp_packets = 0
    number_of_udp_packets = 0


    processed_file = rdpcap(input_file)# read in the pcap file
    # Creates an empty list to store all latencies
    latencies = []
    arrival_time = None
    sessions = processed_file.sessions() #get the list of sessions/TCP connections

    request_info = {} #where we keep request times key "(ip,port) -> linux time"


    for session in sessions:
        for packet in sessions[session]: # for each packet in each session
        
            number_of_packets_total += 1 #increment total packet count
            
            if packet.haslayer(TCP): # check is the packet is a TCP packet
                number_of_tcp_packets += 1 # count TCP packets
                source_ip = packet[IP].src # note that a packet is represented as a python hash table with keys corresponding to
                dest_ip = packet[IP].dst # layer field names and the values of the hash table as the packet field values
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport

                # Filtering packets based on the server's IP address and port number.
                if (source_ip == server_ip and source_port == server_port) or (dest_ip == server_ip and dest_port == server_port):
                
                    if (packet.haslayer(HTTP)): # test for an HTTP packet
        
                        if HTTPRequest in packet: # test for an http request
                            request_id = get_request_id(packet)
                            arrival_time = packet.time # get unix time of the packet

                            #use request_id as key for time
                            if request_id not in request_info:
                                request_info[request_id] = arrival_time
                            else:
                                print("Error: Data already assigned to request ID")

                        if HTTPResponse in packet: # test for an http response
                            response_id = get_response_id(packet)
                            arrival_time = packet.time

                            if response_id in request_info: #if request is found, find latency, remove key
                                latencies.append(packet.time - request_info[response_id])

                                del request_info[response_id]
                            else:
                                print("Error: Response Id not in request dictionary")
                else:

                    continue
            elif (packet.haslayer(UDP)):
                    number_of_udp_packets += 1

    # Check for incomplete transactions
    if request_info:
        print("Not receive a response.")

    return latencies

def calculate_statistics(latencies):
    """Calculate statistics on the latency data from the input file."""

    # Calculating the average
    mean = sum(latencies)/len(latencies)
    print('Average Latency: ', round(mean, 5))

    sorted_latencies = sorted(latencies)

    # Calculating percentiles
    #
    print("Percentiles: ",end="")
    i = 0
    for percentile in [0.25, 0.50, 0.75, 0.95, 0.99]:
        # Calculating the index using nearest rank method
        index = int(round((len(sorted_latencies) + 1) * percentile)) - 1

        # Checks if the index is within the bounds
        index = max(min(index, len(sorted_latencies) - 1), 0)
        print('{}'.format(round(sorted_latencies[index], 5)), end=" ")

        #this is just for the syntax of the commas
        if i <= 3:
            print(' ',end = "")
            i+=1

def get_request_id(packet):
    if TCP in packet:
        request_id = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        return request_id

def get_response_id(packet):
    if TCP in packet:
        response_id = (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport)
        return response_id

# Computes the Kullback-Leibler divergence between two probability distributions
def computing_kullbackLeibler_divergence(latencies):
    modeled_distribution = []
    measured_distribution = []
    kullbackLeibler_divergence = 0

    total_latency = sum(latencies)

    #Calculating the Modeled Distribution
    for latency in latencies:
        modeled_distribution.append(latency/total_latency)
        
    #Calculating the Measurement Distribution
    uniform_distribution = 1/len(latencies)
    measured_distribution = [uniform_distribution] * len(latencies)

    # Calculating the Kullback-Leibler Divergence
    for i in range(len(modeled_distribution)):
        if modeled_distribution[i] != 0:
            kullbackLeibler_divergence += modeled_distribution[i] * math.log(modeled_distribution[i] / measured_distribution[i])
    print(f'\nKL DIVERGENCE: {round(kullbackLeibler_divergence, 5)}')

if __name__ == "__main__":
    main()
