# version 1.0
import os
from collections import Counter

import dpkt
import sys
import logging
import time

import numpy
import numpy as np
import pandas as pd

import BasicFlowInfo
import PacketInfo
from tqdm import tqdm
from matplotlib import pyplot as plt
from sklearn.cluster import Birch, DBSCAN, MeanShift

logging.basicConfig(filename='error.log', level=logging.INFO, format='%(asctime)s\t[%(levelname)s]\t%(message)s')
logger = logging.getLogger(__name__)
flowTimeout = 120
activityTimeout = 10

def deal_packet(packet, CurrentFlow, DestIp):
    rtt = -1
    # 0 out 1 in
    if packet.dst_ip == DestIp:
        direct = 1
    elif packet.src_ip == DestIp:
        direct = 0
    else:
        return rtt

    #超时、syn、Rst和fin-ack结束流
    if CurrentFlow.__contains__(packet.GetfwdFlowId()) or CurrentFlow.__contains__(packet.GetbwdFlowId()):
        if CurrentFlow.__contains__(packet.GetfwdFlowId()):
            id = packet.GetfwdFlowId()
        else:
            id = packet.GetbwdFlowId()
        flow = CurrentFlow[id]
        if (packet.ts - flow.flowStartTime) >= flowTimeout or packet.IsSyn():
            rtt = flow.getRtt()
            del CurrentFlow[id]
            CurrentFlow[packet.GetfwdFlowId()] = BasicFlowInfo.BasicFlow(packet, direct)
        elif packet.IsRst():
            CurrentFlow[id].addpacket(packet, direct)
            rtt = CurrentFlow[id].getRtt()
            del CurrentFlow[id]
        else:
            if flow.FinAck2 == packet.ackNum:
                CurrentFlow[id].addpacket(packet, direct)
                rtt = CurrentFlow[id].getRtt()
                del CurrentFlow[id]
            else:
                CurrentFlow[id].addpacket(packet, direct)
    else:
        if packet.IsRst():
            return rtt
        else:
            CurrentFlow[packet.GetfwdFlowId()] = BasicFlowInfo.BasicFlow(packet, direct)
    return rtt

# 解析pcap包
def parse_pcap(pcap, DestIp, CurrentFlow, lastActiveTime):
    # pcap = pcap.readpkts()
    flows_rtt_list = []
    del_id = []
    for ts, buf in tqdm(pcap):
        #检查是否有不活跃的流，从当前流字典中删除并提前rtt
        if (ts - lastActiveTime) >= activityTimeout:
            for id in CurrentFlow:
                if CurrentFlow[id].lastPktTime <= lastActiveTime:
                    rtt = CurrentFlow[id].getRtt()
                    del_id.append(id)
                    if rtt != -1:
                        flows_rtt_list.append(rtt)
            for kid in del_id:
                del CurrentFlow[kid]
            del_id.clear()
            lastActiveTime = ts
        pk = PacketInfo.Packet(ts, buf)
        #处理数据包，只关注tcp包
        if pk.IsTcp():
            flow_rtt = deal_packet(pk, CurrentFlow, DestIp)
            if flow_rtt != -1:
                flows_rtt_list.append(flow_rtt)
    return flows_rtt_list, lastActiveTime


def Rtt(pcap_file_dir, DestIp):
    pcap_file = None
    CurrentFlow = dict()
    rtt_list = []
    lastActiveTime = 0
    try:
        #读取pcap文件
        for root, dirs, fnames in os.walk(pcap_file_dir):
            for fname in fnames:
                pcap_file = open(os.path.join(root, fname), 'rb')
                pcap_1 = dpkt.pcap.Reader(pcap_file)
                print('parsing {}'.format(fname))
                #解析数据包
                temp_list, lastActiveTime = parse_pcap(pcap_1, DestIp, CurrentFlow, lastActiveTime)
                rtt_list.extend(temp_list)
                print(lastActiveTime)
        #读取未结束的流的rtt
        for key in CurrentFlow:
            rtt = CurrentFlow[key].getRtt()
            if rtt != -1:
                rtt_list.append(rtt)
        logger.info('{}文件夹中共有{}个rtt'.format(root, len(rtt_list)))
        target_type, typenum = numpy.unique(np.array(rtt_list), return_counts=True)

        #去除数量是1的rtt值
        for id in range(len(target_type)):
            if typenum[id] == 1:
                for rtt_key in rtt_list:
                    if rtt_key == target_type[id]:
                        rtt_list.remove(rtt_key)
                        break
        target_type, typenum = numpy.unique(np.array(rtt_list), return_counts=True)
        print('lable:', target_type, 'num:', typenum)
        dataframe = pd.DataFrame({'rtt': rtt_list, 'rtt2': rtt_list})
        dataframe.to_csv("test.csv", index=False)
        rtt_num = len(rtt_list)
        count_num = 0
        #取前90%的rtt值
        for id in range(len(target_type)):
            count_num = count_num + typenum[id]
            if count_num > (rtt_num*90/100):
                for num in range(typenum[id]):
                    rtt_list.remove(target_type[id])
        target_type, typenum = numpy.unique(np.array(rtt_list), return_counts=True)
        print('lable:', target_type, 'num:', typenum)
        print(len(rtt_list))
        rtt_list = np.array(rtt_list).reshape(-1, 1)

        # cluster = Birch(threshold=0.00005, n_clusters=2)
        # labels = cluster.fit_predict(rtt_list)

        # db = DBSCAN(eps=0.0005, min_samples=(len(rtt_list)/20))
        # db.fit(rtt_list)
        # labels = db.labels_
        # n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
        # print('Estimated number of clusters: %d' % n_clusters_)

        ms = MeanShift(bandwidth=0.002, bin_seeding=True)
        ms.fit(rtt_list)
        labels = ms.labels_
        cluster_centers = ms.cluster_centers_
        labels_unique = np.unique(labels)
        n_clusters = len(labels_unique)
        print('n_clusters:', n_clusters)
        print('cluster_centers:', cluster_centers)

        plt.plot(target_type, typenum, color='red', label='rtt')
        #plt.scatter(rtt_list, rtt_list)
        plt.xlabel('rtt')
        plt.ylabel('num')
        plt.xlim(0, 0.01)
        plt.legend()
        plt.show()
    except KeyError:
        logger.error(sys.exc_info()[1])
    finally:
        if pcap_file is not None:
            pcap_file.close()


if __name__ == '__main__':
    # 读取pcap文件夹的路径
    pcap_file_dir = sys.argv[1]
    #读取目标ip
    DestIp = sys.argv[2]
    Rtt(pcap_file_dir, DestIp)
