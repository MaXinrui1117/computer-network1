#数据包信息提取
import socket

import dpkt
import sys
import logging

logger_err = logging.getLogger(__name__)


class Packet:

    def __init__(self, ts, buf):

        self.ts = ts  # 时间戳

        # 一些属性的初始化
        self.layer_3_proto = -1
        self.src_ip = b''
        self.dst_ip = b''
        # self.ip_len = 0
        # self.ip_hlen = 0
        self.layer_4_proto = -1
        self.src_port = -1
        self.dst_port = -1
        #self.tcp_hlen = 0
        self.SYN = 0
        self.ACK = 0
        self.FIN = 0
        self.RST = 0
        self.seqNum = -1
        self.ackNum = -1
        self.payloadlen = 0

        self.__parse_pkt__(buf)

    def __parse_pkt__(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        self.layer_3_proto = eth.type  # 第三层协议
        try:
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:  # 解析ipv4报文
                self.__parse_ip__(eth.data)
            elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:  # 解析ipv6报文
                self.__parse_ip__(eth.data)
            elif eth.type == dpkt.ethernet.ETH_TYPE_8021Q:  # 802.1Q
                self.__parse_dot1q__(eth)
        except Exception:
            logger_err.warning('line __parse_pkt__:{}  {}'.format(sys.exc_info()[1],self.ts))

    def __parse_dot1q__(self, eth):
        try:
            self.layer_3_proto = eth.vlan_tags[0].type
            if eth.vlan_tags[0].type == dpkt.ethernet.ETH_TYPE_IP:
                self.__parse_ip__(eth.data)
            elif eth.vlan_tags[0].type == dpkt.ethernet.ETH_TYPE_IP6:
                self.__parse_ip__(eth.data)
        except Exception:
            logger_err.warning('line __parse_dot1q__:{}  {}'.format(sys.exc_info()[1],self.ts))

    def __parse_ip__(self, ip):
        if self.layer_3_proto == dpkt.ethernet.ETH_TYPE_IP:
            self.src_ip = socket.inet_ntop(socket.AF_INET, ip.src)  # 源IP
            self.dst_ip = socket.inet_ntop(socket.AF_INET, ip.dst)  # 宿IP
        else:
            self.src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)  # 源IP
            self.dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)  # 宿IP
        self.layer_4_proto = ip.p  # 第四层协议
        #self.ip_hlen = ip.hl
        #self.ip_len = ip.len
        if ip.p == dpkt.ip.IP_PROTO_TCP:  # 解析tcp报文
            self.__parse_tcp__(ip.data)

    def __parse_tcp__(self, tcp):
        self.src_port = str(tcp.sport)  # 源端口
        self.dst_port = str(tcp.dport)  # 目的端口
        self.SYN = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        self.ACK = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        self.FIN = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        self.RST = (tcp.flags & dpkt.tcp.TH_RST) != 0
        self.seqNum = tcp.seq
        self.ackNum = tcp.ack
        self.payloadlen = len(tcp.data)

    def GetfwdFlowId(self):
        flowId = self.src_ip + "-" + self.dst_ip + "-" + self.src_port + "-" + self.dst_port + "-" + str(self.layer_4_proto)
        return flowId

    def GetbwdFlowId(self):
        flowId = self.dst_ip + "-" + self.src_ip + "-" + self.dst_port + "-" + self.src_port + "-" + str(self.layer_4_proto)
        return flowId

    def IsTcp(self):
        if self.layer_4_proto == dpkt.ip.IP_PROTO_TCP:
            return True
        else:
            return False

    def IsSyn(self):
        if self.SYN == 1:
            if self.ACK == 1:
                return False
            else:
                return True
        else:
            return False

    def IsSynAndAck(self):
        if self.SYN == 1 and self.ACK == 1:
            return True
        else:
            return False

    def IsAck(self):
        if self.ACK == 1:
            if self.SYN == 1:
                return False
            else:
                return True
        else:
            return False

    def IsFin(self):
        if self.FIN == 1:
            return True
        else:
            return False

    def IsRst(self):
        if self.RST == 1:
            return True
        else:
            return False
