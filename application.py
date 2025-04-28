# Import necessary libraries
import socket
import struct
import argparse
import time
#import os
#import threading

# Function to create DRTP packet with header and optional data
#creates a full packet
## Arguments:
# seq: sequence number (int)
# ack: acknowledgment number (int)
# flags: control flags (int)
# window: receiver window size (int)
# data: optional data payload (bytes), default empty
# Returns:
# The created packet combining header + data, used for sending over the network.
#b means that if user doesnt send any data it will use empty data.
def create_packet(seq, ack, flags, window, data=b''):
    #this creates a binary header. takes the integers and packs them into bytes. HHHH chooses the format
    #in total it should give 8 byte header
    header = struct.pack('!HHHH', seq, ack, flags, window)  # Pack header fields
    return header + data  # Return header + data combined

# Function to parse a received DRTP packet into header fields and data
# what it does is that it unpacks the function and returns the values as they initially were
# Arguments:
# packet: the raw received packet (bytes)
# Returns:
# seq, ack, flags, window, data — useful for the application logic (identifying packet type and payload)
def parse_packet(packet):
    header = packet[:8]  # First 8 bytes are header
    seq, ack, flags, window = struct.unpack('!HHHH', header)  # Unpack header fields
    data = packet[8:]  # Remaining bytes are data
    return seq, ack, flags, window, data

# Server side function to receive file
# Description:
# Listens for client connection, receives file in chunks, handles connection establishment and teardown.
# Arguments:
# ip: server's IP address to bind to (must be in dotted decimal format, e.g., 10.0.1.2)
# port: server's port number (must be between 1024–65535)
# discard_seq: sequence number to simulate packet loss (int)
# Returns:
# None. Server writes the received data to a file ('received_file') and prints throughput at the end.
def server(ip, port, discard_seq):
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Validate IP and port formats
    # (you already implicitly trust args, so no strict validation is added, which is fine in this context)
    sock.bind((ip, port))  # Bind socket to IP and port
    print(f"Server listening on {ip}:{port}")

    # Wait for SYN from client
    #server receives up to 1024 bytes of data
    data, addr = sock.recvfrom(1024)
    #each of those values gets the unpacked header and store it as a variable. the remainder is the payload which could be empty
    seq, ack, flags, window, _ = parse_packet(data)
    #this checks if the syn flag is set.
    if flags & 0b0010:
        print("SYN packet is received")
        # Send SYN-ACK back to client confirming that yes we are ready to establish connection
        sock.sendto(create_packet(0, seq, 0b0110, 15), addr)
        print("SYN-ACK packet is sent")

    # Wait for ACK to complete handshake
    #receive message once again from client.
    data, addr = sock.recvfrom(1024)
    #unpack the received packet from client which is the acked message
    seq, ack, flags, window, _ = parse_packet(data)
    #if the ack flag is set then the server can confirm it and is ready to receice files
    if flags & 0b0100:
        print("ACK packet is received")
        print("Connection established")

    # Open file to write received data
    f = open('received_file', 'wb')
    expected_seq = 1  # Start expecting sequence number 1
    start_time = time.time()
    total_bytes = 0

    while True:
        try:
            #this is where the actual file starts getting reveived. little by little
            #its received and unpacked and chunk represents the payload now
            data, addr = sock.recvfrom(1024)  # Receive packet
            seq, ack, flags, window, chunk = parse_packet(data)


            # If FIN flag is set. this means that you get the flag that concludes the receiving of data.
            if flags & 0b0001:
                print("FIN packet is received")
                # Send FIN-ACK back meaning that the fin is being acknowledged
                sock.sendto(create_packet(0, seq, 0b0101, 0), addr)
                print("FIN ACK packet is sent")
                #end everything here
                break

            # If discarding a packet for testing retransmission
            if seq == discard_seq:
                print(f"Discarding packet {seq} for testing")
                discard_seq = 99999999  # Discard only once
                continue

            # Check if packet has the expected sequence number
            #it always starts at 1 but increments gradually
            if seq == expected_seq:
                #confirms that it has received the packet. gives timeframe hours minute and second
                #and also the packet number
                print(f"{time.strftime('%H:%M:%S')} -- packet {seq} is received")
                # Write chunk to file saving it and it increases as more packets arrive
                f.write(chunk)
                #the variable total chunks increases for every packet
                total_bytes += len(chunk)
                #the next sequence that is expected is increased by 1
                expected_seq += 1
                # Send ACK for received packet consisting of sequence ack flag and window
                sock.sendto(create_packet(0, seq, 0b0100, 0), addr)
                #prints what happened in the previous step
                print(f"{time.strftime('%H:%M:%S')} -- sending ack for the received {seq}")
            else:
                # Ignore out-of-order packets. it is discarded triggering go back N
                print(f"Received unexpected packet {seq}, expecting {expected_seq}")

        #send an error message if file transfer is not successful
        except Exception as e:
            print(f"Error: {e}")
            break

    ## Close file after receiving everything
    f.close()
    #this saves the time after the while loop ended.
    end_time = time.time()
    #this records the total time and saves it as duration
    duration = end_time - start_time
    #using the total amount of time and size of file it is then possible to
    #find the throughput
    #total bytes is converted to bits by multiplying by 8
    #then finally it is divided by time
    throughput = (total_bytes * 8) / (duration * 1_000_000) if duration > 0 else 0
    print(f"The throughput is {throughput:.4f} Mbps")
    #then it announces that the socket is going to get closed and does it
    print("Connection Closes")
    sock.close()

# Client side function to send file
# Description:
# Establishes connection to server, sends file data reliably using a sliding window, and handles teardown.
# Arguments:
# ip: server's IP address to connect to (must be dotted decimal, e.g., 10.0.1.2)
# port: server's port number (must be valid, 1024–65535)
# filename: path to the file to be sent
# window_size: sliding window size for transmission
# Returns:
# None. File is transmitted successfully and connection is closed properly.
def client(ip, port, filename, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #sets timeout to 400 milliseconds
    sock.settimeout(0.4)

    #saves the ip and port into one variable
    server_addr = (ip, port)

    # initializes the Three-way handshake
    # Description:
    # Sends SYN packet to initiate connection, waits for SYN-ACK.
    # If no response from server, catches timeout and prints "Connection failed."
    # Ensures clean exit if server is down or unreachable.
    try:
        #the first sequence which is numbered zero is the syn packet which is the
        #1 in 0010. it also sends window size and the ip and port
        sock.sendto(create_packet(0, 0, 0b0010, window_size), server_addr)
        #confirms that it has sent it
        print("SYN packet is sent")
        #keep in mind that 0010 is synbit 0110 is that it was acked and
        #0001 is a fin bit

        # Wait for SYN-ACK from server side. once received its stored in data
        data, _ = sock.recvfrom(1024)
        #the variable data is then unpacked and divided by the variables
        seq, ack, flags, recv_window, _ = parse_packet(data)
        #this is if the syn packet is acknowledged
        if flags & 0b0110:
            print("SYN-ACK packet is received")

        # Send ACK 0100 confirming that the syn ack was received and that data
        #transfer can begin.
        sock.sendto(create_packet(0, ack, 0b0100, window_size), server_addr)
        print("ACK packet is sent")
        print("Connection established")

    except (socket.timeout, ConnectionResetError):
    # Catches timeout or forced close if server does not respond.
        print("Connection failed")
        sock.close()
        return

    # Read file and split into 992 byte chunks
    #opens the file in binary mode and shortens it to f
    with open(filename, 'rb') as f:
        #makes an array called chunks
        chunks = []
        while True:
            #every chunk is saved as 992 bytes which when combined with the
            #header should be 1000 bytes or 1 Kb. so payload can only be 1000
            #bytes
            chunk = f.read(992)
            #stops when file ends
            if not chunk:
                break
            chunks.append(chunk)

    #starting number of the sliding windows
    base = 1
    # Next sequence number to send
    next_seq = 1
    #actual window size. it takes the lesser of the two values and uses that as window size.
    #it can never exceed 15
    window = min(window_size, recv_window)
    #total number of chunks to send
    total_chunks = len(chunks)

    #send_packets sends all packets from next_seq up to base + window.
    #Creates and sends each packet.
    #Prints a timestamped message showing which packets were sent.
    #Increments next_seq after sending each packet.
    def send_packets():
        nonlocal next_seq
        # Keep sending packets within the window
        while next_seq < base + window and next_seq <= total_chunks:
            packet = create_packet(next_seq, 0, 0, 0, chunks[next_seq - 1])
            sock.sendto(packet, server_addr)
            print(f"{time.strftime('%H:%M:%S')} -- packet with seq = {next_seq} is sent, sliding window = {{{', '.join(map(str, range(base, next_seq+1)))}}}")
            next_seq += 1

    start_time = time.time()

    send_packets()

    while base <= total_chunks:
        try:
            # Waiting for ack for each sliding window
            data, _ = sock.recvfrom(1024)
            #unpacks and looks for the ack flag
            seq, ack, flags, window_recv, _ = parse_packet(data)
            #if received
            if flags & 0b0100:
                #then it prints the timestamp and the sequence number
                print(f"{time.strftime('%H:%M:%S')} -- ACK for packet = {ack} is received")
                #base increments with one
                base = ack + 1
                #packets are sent and the loop continues as long as base
                #is less than total_chunks meaning no more remaining packets
                send_packets()

        # Timeout, retransmit window if 400 ms passes
        except socket.timeout:
            print("Timeout occurred, resending packets")
            #Resets next_seq to base and retransmits packets in the window
            next_seq = base
            #send packets again
            send_packets()

    #duration is found
    end_time = time.time()
    duration = end_time - start_time
    print("DATA Finished")

    # Two-way connection teardown initiated by sending a fin packet
    sock.sendto(create_packet(0, 0, 0b0001, 0), server_addr)
    print("FIN packet is sent")

    #waits for the acknowledgement of the sent fin packet
    data, _ = sock.recvfrom(1024)
    seq, ack, flags, window, _ = parse_packet(data)
    #if received print it
    if flags & 0b0101:
        print("FIN ACK packet is received")

    #then close the socket
    print("Connection Closes")
    sock.close()

# Main function to parse arguments and run server or client
# Description:
# Parses command line arguments and starts either the server or client based on user input.
# Arguments:
# -s/--server: flag to run as server
# -c/--client: flag to run as client
# -i/--ip: target IP address
# -p/--port: target port
# -f/--file: filename (required for client)
# -w/--window: sliding window size (client)
# -d/--discard: sequence number to discard (server)
# Returns:
# None. Executes appropriate role (server or client) as requested by user.
def main():
    #creates parse object and other options with defaults on some
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', action='store_true')
    parser.add_argument('-c', '--client', action='store_true')
    parser.add_argument('-i', '--ip', type=str, default='10.0.1.2')
    parser.add_argument('-p', '--port', type=int, default=8088)
    parser.add_argument('-f', '--file', type=str)
    parser.add_argument('-w', '--window', type=int, default=3)
    parser.add_argument('-d', '--discard', type=int, default=99999999)

    #parses the command line inputs into an args object
    args = parser.parse_args()

    #if server option is chosen then it runs as server with the info below
    if args.server:
        server(args.ip, args.port, args.discard)
    #if client is chosen then it does the same but with client
    elif args.client:
        #gives error message if no file is specified
        if not args.file:
            print("File must be specified with -f when using client mode")
            return
        client(args.ip, args.port, args.file, args.window)
    else:
        print("Please specify --server or --client")

# Start the program
if __name__ == "__main__":
    main()
