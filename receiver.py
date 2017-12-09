#!/usr/bin/python3
#
# this is for COMP9331 assignement 1 written by Prophet.
# test environment:
#
# Python 3.6.2 (v3.6.2:5fd33b5, Jul  8 2017, 04:14:34) [MSC v.1900 32 bit (Intel)] on win32
# Type "help", "copyright", "credits" or "license" for more information.
#
# the input format :
#   python receiver.py receiver_port file.txt

import argparse
import sys
import socket
import struct
import random
import re
import time
from collections import Counter

def parserArgument():
    
    parser = argparse.ArgumentParser(description='the UDP server for reliable data trasmission protocol')

    parser.add_argument('receiver_port',type = int,action = 'store',nargs = '+',help = 'the port for connection')
    parser.add_argument('file',type = str,action = 'store',nargs = '+', help = 'the file that you want to send to the sender')

    argv = parser.parse_args()

    argv.receiver_port = argv.receiver_port[0]
    argv.file = argv.file[0]

    return argv


def create_log(file_name):
    
    sys_log = open(file_name,'w+')
    sys_log.close()
    try:
        log_check = open(file_name,'r+')
    except FileNotFoundError:
        print("the " + file_name + " can not be created.")
        return False

    log_check.close()

    return True

def get_ISN(seed):
    """
    this function can return a initial sequnce number
    """
    random.seed(seed)
    ISN = random.randint(seed,seed * 100)
    return ISN


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

        ###########################
        self.init_time = 0
        self.max_len_file = 0

        self.data_trans_num = 0
        self.data_segm_num = 0
        self.drop_num = 0
        self.resnd_segm_num = 0
        self.Du_ack_num = 0

        self.data_recv = 0


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

def hand_shaking(head,server,seed,buff_size):
    
    # head.data_bytes, addr = server.recvfrom(buff_size)
    # head.unpack_data()
    # head.header_print()
    addr = (head.dest_IP,head.dest_port)
    # print(addr)
    client_ISN = head.seq_num
    # buff_size = len(head.data_bytes) * 2 + head.MSS * 2
    # mess = int(input("\nack_number:")) # seq_num + 1
    head.ack_num = head.seq_num + 1
    head.seq_num = get_ISN(seed)
    ISN = head.seq_num

    # print()
    # head.header_print()

    head.packet_data()

    server.sendto(head.data_bytes,addr)
    record_state(head, 's', 'SA')

    head.data_bytes, addr = server.recvfrom(buff_size)
    head.unpack_data()
    
    record_state(head, 'r', 'A')

    # print()
    # head.header_print()

    if head.ack_num == ISN + 1 and head.seq_num == client_ISN + 1:
        print('three-way handshaking is complete. \nclient, good job!!\n waiting for data...')
        return True
    else:
        pass
    return False

def recv_four_final(head, server, buff_size):
    # print("\n---------------------------------\n")
    # print('the 1st recv')
    # head.header_print()

    head.SYN = False
    head.FIN = False
    head.ack_num, head.seq_num = head.seq_num + 1, head.ack_num
    third_ack, third_seq = head.ack_num, head.seq_num

    # print('2nd before send')
    # head.header_print()

    head.packet_data()
    # print()
    # head.header_print()
    server.sendto(head.data_bytes, (head.dest_IP, head.dest_port))
    record_state(head, 's', 'FA')
    time.sleep(0.5)

    head.FIN = True
    head.SYN = False
    head.packet_data()

    # print('3rd before send ')
    # head.header_print()

    server.sendto(head.data_bytes, (head.dest_IP, head.dest_port))
    record_state(head, 's', 'F')

    head.data_bytes, addr = server.recvfrom(buff_size)
    head.unpack_data()

    record_state(head, 'r', 'A')

    # print('4th recv')
    # head.header_print()

    if head.ack_num == third_seq + 1 and head.seq_num == third_ack:
        print("\nFIN is complete.\n well done, client!!! \n waiting to write content into file and closing\n")
        return True
    else:
        pass

    return False


def find_interval(ack_list):
    """
    this function can find the minimum interval number in acknowledge number list

    >>> find_interval([0, 1, 2, 3])
    4
    >>> find_interval([0, 1, 2, 3, 7, 4, 9, 5])
    6
    >>> find_interval([0, 1, 2, 3, 7, 4, 9, 5])
    """
    interval = 0
    while interval in ack_list:
        interval += 1
    return interval


def record_state(head, mode, type_packet):
    """
    this can record the state into the log file
    """
    now_time = (time.time() - head.init_time) * 1000
    now_time = round(now_time, 2)
    mode_dic = {'s': 'snd', 'r': 'rcv', 'd': 'drop'}
    len_byte = len(head.data)
    # head.header_print()3
    # log_context = "{:<4}  ".format(mode_dic[mode]) + "{:<{}}  ".format(str(now_time), 10) + "{:<2}  ".format(type_packet) + \
    #               "{:<{}}  ".format(head.seq_num, head.max_len_file//head.MSS) + "{:<{}}  ".format(len_byte, head.MSS) + \
    #               "{:<{}}  ".format(head.ack_num, head.max_len_file//head.MSS) + '\n'
    log_context = "{:<4}  ".format(mode_dic[mode]) + "{:<{}}  ".format(str(now_time), 10) + "{:<2}  ".format(type_packet) + \
                  "{:<{}}  ".format(head.seq_num, 10) + "{:<{}}  ".format(len_byte, 10) + \
                  "{:<{}}  ".format(head.ack_num, 10) + '\n'

    # print(log_context)
    log_file = open('Receiver_log.txt', 'a')
    log_file.write(log_context)
    log_file.close()

    return


def main():

    argv = parserArgument()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('',argv.receiver_port))
    recv_head = Header()
    buff_size = 4096
    recv_seed = int(time.time() // 100000)

    max_len = int(server.recvfrom(1024)[0].decode('ascii')) # this is only for the progress bar

    recv_head.data_bytes, addr = server.recvfrom(buff_size)
    recv_head.unpack_data()

    max_len //= recv_head.MSS  # this is only for the progress bar
    max_len += 1               # this is only for the progress bar

    create_log("Receiver_log.txt")
    recv_head.init_time = time.time()

    hand_shaking(recv_head, server, recv_seed, buff_size)
    recv_head.ack_num = 0
    recv_head.seq_num = 0
    ack_list = [] # the acknowledge number history list, use this to check the data completeness
    recv_dict = {} # all data will be stored in this dictionary 



    while True:

        recv_head.data_bytes, addr = server.recvfrom(buff_size)
        recv_head.unpack_data()

        record_state(recv_head, 'r', 'D')
        # print("*********************Receive********************************")
        # print('the seq is {}'.format(recv_head.seq_num))
        # print('the data is {}'.format(recv_head.data))
        # print("************************************************************")

        progres = len(list(set(ack_list)))
        print('\r[' + '>>' * (int(progres/max_len*20))  + ' '*(20 - int(progres/max_len*20)) * 2 + ']  ' + str(int(progres/max_len * 100)) + '%', end='')

        # print('\r' + '>>' * (inx // 10), end='')
        if recv_head.FIN == True:
            break
        recv_dict[recv_head.seq_num] = recv_head.data
        ack_list.append(recv_head.seq_num // recv_head.MSS)
        interval = find_interval(ack_list)
        # print('the ack_list is {}'.format(ack_list))

        recv_head.seq_num = recv_head.ack_num
        if interval > max(ack_list):
            recv_head.ack_num = (interval-1) * recv_head.MSS + len(recv_dict[(interval-1) * recv_head.MSS])
        else:
            recv_head.ack_num = interval * recv_head.MSS
        recv_head.data = ''
        # print("=====================Send=================================")
        # print('the ack is {}'.format(recv_head.ack_num))
        # print('the seq is {}'.format(recv_head.seq_num))
        # print("==========================================================")
        recv_head.packet_data()
        server.sendto(recv_head.data_bytes, addr)
        record_state(recv_head, 's', 'D')

    recv_four_final(recv_head, server, buff_size)
    over_write_num = sum([Counter(ack_list)[i] for i in Counter(ack_list)])

    index_list = list(set(ack_list))
    over_write_num -= len(index_list)

    index_list.sort()
    index_list = [i * recv_head.MSS for i in index_list]
    content_list = [recv_dict[indexs] for indexs in index_list]
    content_str = ''.join([recv_dict[indexs] for indexs in index_list])

    create_log(argv.file)
    file_store = open(argv.file, 'w+')
    file_store.write(content_str)
    file_store.close()

    # print('the file content is:')
    # print(content_str)

    print("the transmission is complete.")

    # print('Amount of (original) Data Received (in bytes) – do not include retransmitted data is {}'.format(len(content_str)))
    # print('Number of (original) Data Segments Received'.format(len(content_list)))
    # print('Number of duplicate segments received (if any)'.format(over_write_num))

    print("waiting to write statistics into Sender_log.txt...")
    statistic_context = '\n\n\n' + "#" + '-' * 25 + "statistics" + '-' * 25 + "#\n\n\n" + \
                        'Amount of (original) Data Received (in bytes) – do not include retransmitted data is {}'.format(len(content_str)) + '\n' + \
                        'Number of (original) Data Segments Received is {}'.format(len(content_list)) + '\n' + \
                        'Number of duplicate segments received (if any) is {}'.format(over_write_num) + '\n'

    # print(statistic_context)

    log_file_snd = open("Receiver_log.txt", 'a')
    log_file_snd.write(statistic_context)
    log_file_snd.close()

    print("OK, all have done.")

    server.close()
    
    return

if __name__ == '__main__':
    main()
    # import doctest
    # doctest.testmod()