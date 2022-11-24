import socket
import select

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
# This makes server listen to new connections
server_socket.listen()
# List of sockets for select.select()
sockets_list = [server_socket]
# List of connected clients - socket as a key, user header and name as data
clients = {}
# for storing the ARP requesting clients
print(f'Listening for connections on {IP}:{PORT}...')
subnet_mask = "255.255.255.0"
network = "168.173.10."
available_ip = [True] * 254
available_ip[0] = False


# Handles message receiving
def receive_message(client_socket):
    try:
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:
        return False


while True:

    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            user = receive_message(client_socket)
            if user is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user
            # print('Accepted new connection from username IP: {}'.format(user['data'].decode('utf-8')))

            # Else existing socket is sending a message
        else:
            # Receive message
            message = receive_message(notified_socket)
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue
                # Get user by notified socket, so we will know who sent the message
            user = clients[notified_socket]

            print(f'Received DHCP request from client {user["data"].decode("utf-8")}:')
            ARP_packet = message["data"].decode("utf-8").split()
            if ARP_packet[0] == "Release":
                print("releasing")
                index = ARP_packet[1][11:]
                index = int(index)
                available_ip[index] = True
                DHCP_reply = "0.0.0.0"
                DHCP_reply = DHCP_reply.encode('utf-8')
                DHCP_header = f"{len(DHCP_reply):<{HEADER_LENGTH}}".encode('utf-8')
                notified_socket.send(user['header'] + DHCP_header + DHCP_reply)
                print("DHCP reply sent")

            if ARP_packet[0] == "Request":
                print("requesting")
                for i in range(1, 254):
                    if available_ip[i]:
                        available_ip[i]=False
                        print("available")
                        DHCP_reply = network + str(i)
                        print(DHCP_reply)
                        DHCP_reply = DHCP_reply.encode('utf-8')
                        DHCP_header = f"{len(DHCP_reply):<{HEADER_LENGTH}}".encode('utf-8')
                        notified_socket.send(user['header'] + DHCP_header + DHCP_reply)
                        print("DHCP reply sent")
                        break

        # It's not really necessary to have this, but will handle some socket exceptions just in case
    for notified_socket in exception_sockets:
        # Remove from list for socket.socket()
        sockets_list.remove(notified_socket)

        # Remove from our list of users
        del clients[notified_socket]
