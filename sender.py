#!/usr/bin/python3
#
# this is for COMP9331 assignement 1 written by Prophet.
# test environment:
#
# Python 3.6.2 (v3.6.2:5fd33b5, Jul  8 2017, 04:14:34) [MSC v.1900 32 bit (Intel)] on win32
# Type "help", "copyright", "credits" or "license" for more information.
#
# the input format :
# python sender.py receiver_host_ip receiver_port file.txt MWS MSS timeout pdrop seed

#  ------------------------------------------------------------------------------------------------------------
# | source IP   | destination IP   | sequence | acknowledge |  SYN  |  FIN  |  MSS  |  MWS  |  data  |  DATA   |
# | source port | destination port |  number  |    number   |  Bit  |  Bit  |  num. |  num. | length | payload |
#  ------------------------------------------------------------------------------------------------------------

import argparse
import sys
import socket
import struct
import random
import re
import time
import threading
import queue

def parserArgument():
    
    parser = argparse.ArgumentParser(description='the UDP clinet for reliable data trasmission protocol')

    parser.add_argument('receiver_host_ip',type = str,action = 'store',nargs = '+',help = 'the ip address of sever')
    parser.add_argument('receiver_port',type = int,action = 'store',nargs = '+',help = 'the port for connection')
    parser.add_argument('file',type = str,action = 'store',nargs = '+', help = 'the file that you want to send to the server')
    parser.add_argument('MWS',type = int,action = 'store',nargs = '+',help = 'Maximum window size in bytes')
    parser.add_argument('MSS',type = int,action = 'store',nargs = '+',help = 'Maximum Segment Size in bytes')
    parser.add_argument('timeout',type = int,action = 'store',nargs = '+',help = 'setting the timeout in (ms)')
    parser.add_argument('pdrop',type = float,action = 'store',nargs = '+')
    parser.add_argument('seed',type = int,action = 'store',nargs = '+')

## this part is changing the format of argv.file[0] -> argv.file
    argv = parser.parse_args()
    argv.receiver_host_ip = argv.receiver_host_ip[0]
    argv.receiver_port = argv.receiver_port[0]
    argv.file = argv.file[0]
    argv.MWS = argv.MWS[0]
    argv.MSS = argv.MSS[0]
    argv.timeout = argv.timeout[0] / 1000
    argv.pdrop = argv.pdrop[0]
    argv.seed = argv.seed[0]

    return argv

def get_ISN(seed):
    """
    this function can return a initial sequnce number
    """
    ISN = random.randint(seed,seed * 100)
    return ISN

def read_file(path):
    """
    reading the file that will be sent to server
    """
    try:
        send_file = open(path,'r')
        content = send_file.read()
    except FileNotFoundError:
        print("the file that you found does not exist.")
    send_file.close()
    return content

def create_log(file_name):
    """
    create a system log
    """
    sys_log = open(file_name,'w+')
    sys_log.close()
    try:
        log_check = open(file_name,'r+')
    except FileNotFoundError:
        print("the " + file_name + " can not be created.")
        return False

    log_check.close()

    return True


def record_state(head, mode, type_packet):
    """
    this can record the state into the log file

    """
    now_time = (time.time() - head.init_time) * 1000
    now_time = round(now_time, 2)
    mode_dic = {'s': 'snd', 'r': 'rcv', 'd': 'drop'}
    len_byte = len(head.data)
    if mode == 's':
        head.data_segm_num += 1
    elif mode == 'r':
        pass
    elif mode == 'd':
        head.drop_num += 1
    else:
        pass
    # head.header_print()
    # log_context = "{:<4}  ".format(mode_dic[mode]) + "{:<{}}  ".format(str(now_time), 10) + "{:<2}  ".format(type_packet) + \
    #               "{:<{}}  ".format(head.seq_num, head.max_len_file//head.MSS) + "{:<{}}  ".format(len_byte, head.MSS) + \
    #               "{:<{}}  ".format(head.ack_num, head.max_len_file//head.MSS) + '\n'
    log_context = "{:<4}  ".format(mode_dic[mode]) + "{:<{}}  ".format(str(now_time), 10) + "{:<2}  ".format(type_packet) + \
                  "{:<{}}  ".format(head.seq_num, 10) + "{:<{}}  ".format(len_byte, 10) + \
                  "{:<{}}  ".format(head.ack_num, 10) + '\n'

    # print(log_context)
    log_file = open('Sender_log.txt', 'a')
    log_file.write(log_context)
    log_file.close()

    return


def check_form_address(host_address):
    """
    check IP format
    """
    check_format = re.findall(r'(\d+)\.(\d+)\.(\d+)\.(\d+)',host_address)
    if len(check_format) == 0:
        return False
    else:
        check_number = host_address.split('.')
        check_number = [int(i)//255 for i in check_number]
        if any(check_number) is not False:
            return False
        else:
            return True


def chop_file(content, MSS):
    """
    this function can chop the file into several chunks

    >>> s = 'wsdfgbgfe'
    >>> t = 'kjhgyuiolkjhg'
    >>> chop_file(s, 3)
    [b'wsd', b'fgb', b'gfe']
    >>> chop_file(t, 3)
    [b'kjh', b'gyu', b'iol', b'kjh', b'g']
    """
    # send_string = content.encode('ascii')
    send_string = content
    send_list = [send_string[i:i+MSS] for i in range(0,len(send_string), MSS)]
    return send_list


def gener_file_dic(content, MSS):
    """
    this function can generate the send dictionary

    >>> s = 'wsdfgbgfe'
    >>> t = 'kjhgyuiolkjhg'
    >>> gener_file_dic(s,3)
    {0: b'wsd', 3: b'fgb', 6: b'gfe'}
    >>> gener_file_dic(t,4)
    {0: b'kjhg', 4: b'yuio', 8: b'lkjh', 12: b'g'}
    """
    dictionary = {}
    send_list = chop_file(content,MSS)
    for i in range(len(send_list)):
        dictionary[i*MSS] = send_list[i]
    return dictionary


class Header():
    def __init__(self):
        self.Source_IP = '127.45.23.1'
        self.Source_port = 80
        self.dest_IP = '127.0.0.1'
        self.dest_port = 80
        self.seq_num = 90
        self.ack_num = -1
        self.SYN = True
        self.FIN = False
        self.MSS = 34
        self.MWS = 45
        self.data = 'yui'
        self.data_len = 0
        self.data_bytes = b''
        ###############this part is for the log file##############
        self.init_time = 0
        self.max_len_file = 0

        self.data_trans_num = 0
        self.data_segm_num = 0
        self.drop_num = 0
        self.resnd_segm_num = 0
        self.Du_ack_num = 0

    def packet_segment(self, send_string_unpackaged, header):
        """
        header = (
            (source IP, source port), 
            (destination IP, destination port), 
            sequence number, 
            acknowledge number, 
            SYN, 
            FIN, 
            MSS, 
            MWS, 
            data length
        )
        if sequence number is initial sequence unmber then the acknowledge number is negative number.
        a = struct.pack('21s21sIi??III21s',b'('127.0.0.1', 80)', b'('129.0.1.1', 80)', 80, 89 , True, False, 34, 45, 56)
        /---------------------------------------------------------------------------------------------------------------------------------\
        | SIp prot | DIP port | source IP   | destination IP   | sequence | acknowledge |  SYN  |  FIN  |  MSS  |  MWS  |  data  |  DATA   |
        |  length  |  length  | source port | destination port |  number  |   number    |  Bit  |  Bit  |  num. |  num. | length | payload |
        \---------------------------------------------------------------------------------------------------------------------------------/

        >>> h = Header()
        >>> h.unpack_segment(h.packet_segment(b'yui', [('127.45.23.1', 80), ('127.0.0.1', 80), 90, -1, True, False, 34, 45]))
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 3, b'yui')
        >>> h.unpack_segment(h.packet_segment(b'', [('127.45.23.1', 80), ('127.0.0.1', 80), 90, -1, True, False, 34, 45]))
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 1, b'\\x00')
        """

        data_len = len(send_string_unpackaged)

        # if data_len == 0:
        #     data_len += 1
        # else:
        #     pass

        source_header = str(header[0]).encode('ascii')
        destination_header = str(header[1]).encode('ascii')
        send_bytes = struct.pack('=II{}s{}sIi??III{}s'.format(len(source_header),len(destination_header), data_len),
                                len(source_header),
                                len(destination_header),  
                                source_header,
                                destination_header,
                                header[2], header[3], header[4], header[5], header[6], header[7],
                                data_len, send_string_unpackaged)

        return send_bytes

    def packet_data(self):
        """
        this can package the data

        >>> a = Header()
        >>> aa = a.packet_data()
        >>> a.unpack_segment(a.data_bytes)
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 3, b'yui')
        """
        send_content = self.data.encode('ascii')
        head = [(self.Source_IP, self.Source_port), (self.dest_IP, self.dest_port), self.seq_num, self.ack_num, self.SYN, self.FIN, self.MSS, self.MWS]
        self.data_bytes = self.packet_segment(send_content,head)
        
        return self.data_bytes

    def unpack_segment(self,segment_bytes):
        """
        this function can decode the segment bytes

        >>> h = Header()
        >>> a = struct.pack('=II19s17sIi??III3s', 19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 3, b'yui')
        >>> h.unpack_segment(a)
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 3, b'yui')
        >>> b = struct.pack('=II19s17sIi??III1s', 19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 1, b'')
        >>> h.unpack_segment(b)
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 1, b'\\x00')
        """
        I_size = struct.calcsize('I')
        source_length = struct.unpack('=I', segment_bytes[:I_size])[0]
        destination_lenth = struct.unpack('=I', segment_bytes[I_size:I_size*2])[0]
        basis = I_size*2 + source_length + destination_lenth + I_size + struct.calcsize('i') + 2 + 2*I_size
        # print(basis)
        # print(segment_bytes[basis: basis + I_size])
        data_len = struct.unpack("=I", segment_bytes[basis: basis + I_size])[0]
        segment = struct.unpack('=II{}s{}sIi??III{}s'.format(source_length, destination_lenth, data_len),segment_bytes)

        return segment

    def unpack_data(self):
        """
        this function can unpackage data into the data_bytes of class Header

        >>> h = Header()
        >>> aa = h.packet_data()
        >>> h.unpack_data()
        (19, 17, b"('127.45.23.1', 80)", b"('127.0.0.1', 80)", 90, -1, True, False, 34, 45, 3, b'yui')
        >>> h.header_print()
        """
        self.data_bytes = self.unpack_segment(self.data_bytes)
        source, destination, self.seq_num, self.ack_num, self.SYN, self.FIN, self.MSS, self.MWS = self.data_bytes[2:10]
        self.data = self.data_bytes[-1].decode('ascii')
        self.data_len = len(self.data)
        # print(eval(destination.decode('ascii')))
        (self.Source_IP, self.Source_port) = eval(destination.decode('ascii'))
        (self.dest_IP, self.dest_port) = eval(source.decode('ascii'))

        return self.data_bytes


    def header_print(self):
        """
        this funciton is used in debugging to print the header content.

        >>> a = Header()
        >>> a.header_print()
        """
        print("the source IP is ({}, {})".format(self.Source_IP, self.Source_port))
        print("the destination IP is ({}, {})".format(self.dest_IP, self.dest_port))
        print('the sequence number is {}'.format(self.seq_num))
        print('the acknowledge number is {}'.format(self.ack_num))
        print('the SYN is {}'.format(bool(self.SYN)))
        print("the FIN is {}".format(bool(self.FIN)))
        print('the MSS is {}'.format(self.MSS))
        print('the MWS is {}'.format(self.MWS))
        print('the data is {}'.format(self.data))
        print('the length of data is {}'.format(self.data_len))
        print('the data_bytes is {}'.format(self.data_bytes))

        return

def PLD_possible(pdorp):
    if pdorp <= 1:
        if random.random() < pdorp:
            return True
        else:
            return False
    else:
        pass
    return False


# def PLD_send(skt_pld, address, send_content, pdrop):
def PLD_send(skt_pld, address, head, pdrop):
    """
    this fucntion use the PLD model to send the file content
    skt_pld is the socket class
    address is (host_ip, port)
    send_content is in bytes
    pdrop is the possiblity of droping packets
    seed is for initial the random number generator
    """
    send_content = head.data_bytes
    if PLD_possible(pdrop) is False:
        skt_pld.sendto(send_content,address)
        record_state(head, 's', 'D')
        # head.data_segm_num += 1
    else:
        record_state(head, 'd', 'D')
        # head.drop_num += 1
    return

def first_handshake_send(client, head, seed):
    
    client.sendto(str(head.max_len_file).encode('ascii'), (head.dest_IP, head.dest_port))

    head.SYN = True
    head.FIN = False
    head.ack_num = -1
    head.seq_num = get_ISN(seed)
    head.data = ''
    head.data_len = len(head.data)
    head.packet_data()
    # head.header_print()
    client.sendto(head.data_bytes,(head.dest_IP, head.dest_port))
    record_state(head, 's', 'S')

    return head.seq_num

def three_way_handshaking(client, head, seed):
    seq = first_handshake_send(client,head,seed)
    head.data_bytes, addr = client.recvfrom(1024)
    head.unpack_data()
    record_state(head, 'r', 'SA')

    # print()
    # head.header_print()

    if head.ack_num == seq + 1:
        print("three-way handshaking is complete.\n server, good job!!!\n ready to transmit...")
        head.ack_num = head.seq_num + 1
        head.SYN = False
        head.seq_num = seq + 1
        # print()
        # head.header_print()
        head.packet_data()
        client.sendto(head.data_bytes,addr)
        record_state(head, 's', 'A')
        return True
    else:
        pass
    return False


def sender_four_fin(client, head, ack_no, seq_no, buff_size):
    # print("\n---------------------------\n")
    head.FIN = True
    head.SYN = False 
    head.ack_num = ack_no
    head.seq_num = seq_no
    head.data = ''
    head.data_len = len(head.data)
    head.packet_data()

    # print('1st before send')
    # head.header_print()

    client.sendto(head.data_bytes, (head.dest_IP, head.dest_port))
    record_state(head, 's', 'F')
    head.data_bytes, addr = client.recvfrom(buff_size)
    head.unpack_data()
    record_state(head, 'r', 'FA')

    # print('2nd recv')
    # head.header_print()

    # if head.seq_num != ack_no or head.ack_num != seq_no + 1:
    while head.seq_num != ack_no or head.ack_num != seq_no + 1:
        # print('Hey server! f**k you!!!')
        # print("waiting for FA from receiver")
        head.data_bytes, addr = client.recvfrom(1024)
        head.unpack_data()
        # return False
    else:
        head.data_bytes, addr = client.recvfrom(buff_size)
        head.unpack_data()
        record_state(head, 'r', 'F')

        # print('3rd recv')
        # head.header_print()

        if head.FIN != True or head.SYN != False:
            # print("waiting for FA from receiver")
            # print('Hey server! f**k you!!!')
            return False
        else:
            head.ack_num, head.seq_num= head.seq_num + 1, head.ack_num
            head.FIN, head.SYN = False, False
            head.packet_data()

            # print('4th before send')
            # head.header_print()

            client.sendto(head.data_bytes, (head.dest_IP, head.dest_port))
            record_state(head, 's', 'A')

            print("server, Well done!!! \nprepare for closing...\n")

            time.sleep(3)
            client.close()
            # sys.exit()
            return True

    return False

def DACK_number(DACK_list):
    DACK = max(DACK_list)
    amount_DANCK = DACK_list.count(DACK) % 3 + 1
    return DACK, amount_DANCK

# def client_send(data_seq, client, send_head, data_dict, send_seq_list):
#     addr = (send_head.dest_IP, send_head.dest_port)
#     send_head.seq_num = send_seq_list[data_seq]
#     send_head.data = data_dict[send_head.seq_num]
#     send_head.packet_data()
#     client.sendto(send_head.data_bytes, addr)# !!!!!!!!!!!!!!!!PLD
#     return

def client_send_PLD(data_seq, client, send_head, data_dict, send_seq_list, pdrop):
    addr = (send_head.dest_IP, send_head.dest_port)
    send_head.seq_num = send_seq_list[data_seq]
    send_head.data = data_dict[send_head.seq_num]
    send_head.packet_data()
    PLD_send(client, addr, send_head, pdrop)
    return

def send_process(client, send_head, send_dict, argv, len_file_content):

    addr = (send_head.dest_IP, send_head.dest_port)
    send_seq_list = list(send_dict)
    packet_num = [j for j in range(len(send_seq_list))]
    LBS = 0                         # set initial  lastBytesSent
    LBA = 0                         # set initial  lastBytesAcked
    MWSC = send_head.MWS // send_head.MSS                           # the amount of packets not in bytes 
    LBA_list = []

    while True:  # the condition need to change ack is the same as the len of file 
        for s in packet_num[LBS: LBS + MWSC - (LBS - LBA)]:
            # client_send(LBS + s, client, send_head, send_dict, send_seq_list)
            client_send_PLD(s, client, send_head, send_dict, send_seq_list,argv.pdrop)
        # for s in range(MWSC - (LBS - LBA)):
        #     client_send(LBS + s, client, send_head, send_dict, send_seq_list)
            # send_head.seq_num = send_seq_list[LBS + s + 1]
            # send_head.data = send_dict[send_head.seq_num]
            # send_head.packet_data()
            # client.sendto(send_head.data_bytes, addr)# !!!!!!!!!!!!!!!!PLD

        LBS = LBS + MWSC - (LBS - LBA)

        # print('\nthe window is {}'.format(packet_num[LBA: LBA + MWSC]))

        try :
            send_head.data_bytes = data_que.get(timeout = argv.timeout)
            # data_que.task_done()
            send_head.unpack_data()
            record_state(send_head, 'r', 'A')
            # if send_head.ack_num == (len_file_content//send_head.MSS + 1) * send_head.MSS:
            # if send_head.ack_num == len(send_seq_list) * send_head.MSS:
            if send_head.ack_num == len_file_content:
                break
            LBA = send_head.ack_num // send_head.MSS # acknowledged number // MSS + 1 - 1  convert the acknowledge number into the sequence packets
            LBA_list.append(LBA)
        except queue.Empty:
            # print('time out sending the ack {}'.format(LBA + 1))

            # print('time out sending the ack {}'.format(LBA))

            # client_send_PLD(LBA + 1, client, send_head, send_dict, send_seq_list,argv.pdrop)

            client_send_PLD(LBA , client, send_head, send_dict, send_seq_list, argv.pdrop)
            send_head.resnd_segm_num += 1

            # client_send(LBA + 1, client, send_head, send_dict, send_seq_list)
            # send_head.seq_num = send_seq_list[LBA + 1]
            # send_head.data = send_dict[send_head.seq_num]
            # send_head.packet_data()
            # client.sendto(send_head.data_bytes, addr) #!!!!!!!!!!!!!!!!!!!!!!!!!!!PLD
            continue

        # print('\nthe LBA history list {}'.format(LBA_list))

        DACK, DACK_times = DACK_number(LBA_list)
        # fast retransmission 
        if DACK_times >= 2:
            send_head.Du_ack_num += 1
            if DACK_times == 3:
                client_send_PLD(DACK, client, send_head, send_dict, send_seq_list, argv.pdrop)
                # print("FR mode sending ack{}".format(DACK))
                send_head.resnd_segm_num += 1



            # client_send(DACK + 1, client, send_head, send_dict, send_seq_list)
            # send_head.seq_num = send_seq_list[DACK + 1]
            # send_head.data = send_dict[send_head.seq_num]
            # send_head.packet_data()
            # client.sendto(send_head.data_bytes, addr) #!!!!!!!!!!!!!!!!!!!!!!!!!!!PLD
            # client.sendto(send_seq_list[DACK + 1], addr) 
        else :
            continue
    return


def recv_process(client, len_file_content):
    rec = Header()
    while True:   # the condition need to change ack is the same as the len of file 
        data, addr = client.recvfrom(1024)
        data_que.put(data)
        rec.data_bytes = data
        rec.unpack_data()
        # if rec.ack_num == (len_file_content//rec.MSS + 1) * rec.MSS:
        if rec.ack_num == len_file_content:
            break
    return


def main():
    argv = parserArgument()
    # print(argv.file)
    file_content = read_file(argv.file)
    len_file_content = len(file_content)
    # print(len_file_content)
    log_file = create_log('Sender_log.txt')
    # print(log_file)
    send_dict = gener_file_dic(file_content,argv.MSS)
    # print(send_dict)
    # print('\n\n\n')
    random.seed(argv.seed)
    
    try :
        if check_form_address(argv.receiver_host_ip) is False:
            raise ValueError
    except ValueError:
        print("Sorry sir, There are something wrong with the format of IP address")
        sys.exit()

    # configuration of the UDP protocol
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    destination_IP = argv.receiver_host_ip
    destination_port = argv.receiver_port
    destination_header = (destination_IP,destination_port)

    # client.connect(destination_header)
    client.bind(('127.0.0.1', 9090))
    source_IP = client.getsockname()[0]
    source_port = client.getsockname()[1]

    send_head = Header()
    # ------------------------------------------------------------------------------------------
    # | source IP   | destination IP   | sequence | acknowledge |  SYN  |  FIN  |  MSS  |  MWS  |
    # | source port | destination port |  number  |   number    |  Bit  |  Bit  |  num. |  num. |
    # ------------------------------------------------------------------------------------------
    send_head.Source_IP = source_IP
    send_head.Source_port = source_port
    send_head.dest_IP = destination_IP
    send_head.dest_port = destination_port
    send_head.MSS = argv.MSS
    send_head.MWS = argv.MWS
    send_head.ack_num = 0
    buff_size = 4096
    #------------this part is for log file-------------
    send_head.init_time = time.time()
    send_head.max_len_file = len_file_content
    send_head.data_segm_num = 0
    send_head.drop_num = 0
    send_head.Du_ack_num = 0
    send_head.resnd_segm_num = 0

    # parameter = (
    #     (source IP, source port), 
    #     (destination IP, destination port), 
    #     sequence number, 
    #     acknowledge number, 
    #     SYN, 
    #     FIN, 
    #     MSS, 
    #     MWS, 
    #     data length
    # )

    three_way_handshaking(client, send_head, argv.seed)
    send_head.seq_num = 0
    send_head.ack_num = 0
    send_p = threading.Thread(target = send_process, args=(client, send_head, send_dict, argv, len_file_content))
    recv_p = threading.Thread(target = recv_process, args=(client, len_file_content))

    for target in (send_p, recv_p):
        target.start()

    for target in (send_p, recv_p):
        target.join()
    print("transmission is done!!, close the connection")

    seq_fin = get_ISN(argv.seed)
    ack_fin = get_ISN(argv.seed)
    sender_four_fin(client, send_head, ack_fin, seq_fin, buff_size)

    print("\nwaiting to write statistics into Sender_log.txt...")
    statistic_context = '\n\n\n' + "#" + '-' * 25 + "statistics" + '-' * 25 + "#\n\n\n" + \
                        'Amount of (original) Data Transferred is {}'.format(send_head.max_len_file) + '\n' + \
                        'Number of Data Segments Sent (excluding retransmissions) is {}'.format(send_head.data_segm_num) + '\n' + \
                        'Number of (all) Packets Dropped (by the PLD module) is {}'.format(send_head.drop_num) + '\n' + \
                        'Number of Retransmitted Segments is {}'.format(send_head.resnd_segm_num) + '\n' + \
                        'Number of Duplicate Acknowledgements received is {}'.format(send_head.Du_ack_num) + '\n'
                   
    # print(end_content)

    log_file_snd = open("Sender_log.txt", 'a')
    log_file_snd.write(statistic_context)
    log_file_snd.close()

    print("OK, all have done.")

    return



if __name__ == '__main__':
    data_que = queue.Queue()
    main()
    # import doctest
    # doctest.testmod()
