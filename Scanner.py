import os
import joblib
from scapy.all import *
from collections import Counter

basepath = os.path.dirname(__file__)

# model = joblib.load(r"Model/rf_model.joblib")
model = None

def get_pcap_from_file(file_path):
    """
    This function returns the PCAP object of a file in a specified folder.
    :param folder_path: The path of the folder where the file is located.
    :param file_name: The name of the file.
    :param ext: The extension of the file.
    :return: The PCAP object of the file.
    """
    if os.path.isfile(file_path):
        return rdpcap(file_path)
    else:
        return False


def scan(file_path):
    pcap = get_pcap_from_file(file_path)
    if not pcap:
        return False
    else:
        duration = 0
        logged_in = 0
        count = len(pcap)
        serror_count = 0
        srv_serror_count = 0
        rerror_count = 0
        srv_rerror_count = 0
        same_srv_count = 0
        diff_srv_count = 0
        dst_host_count = 0
        dst_host_srv_count = 1
        dst_host_same_srv_count = 0
        dst_host_diff_srv_count = 0
        dst_host_same_src_port_count = 0
        dst_host_srv_diff_host_count = 0
        dst_host_serror_count = 0
        dst_host_srv_serror_count = 0
        dst_host_rerror_count = 0
        dst_host_srv_rerror_count = 0

        # Loop through each packet in the PCAP file
        for pkt in pcap:
            try:
                # Check for IP layer
                if pkt.haslayer(IP):

                    # Calculate duration
                    if duration == 0:
                        start_time = pkt.time
                    end_time = pkt.time
                    duration = end_time - start_time

                    # Count logged-in connections
                    if "login" in str(pkt["TCP"].payload).lower():
                        logged_in += 1

                    # Count different types of errors
                    if "error" in str(pkt["TCP"].flags).lower():
                        if pkt["TCP"].dport == 22:
                            serror_count += 1
                        elif pkt["TCP"].sport == 22:
                            srv_serror_count += 1
                        else:
                            rerror_count += 1
                    if "rst" in str(pkt["TCP"].flags).lower():
                        if pkt["TCP"].dport == 22:
                            srv_rerror_count += 1

                    # Count same/different service and host connections
                    if pkt["TCP"].dport == pkt["TCP"].sport:
                        same_srv_count += 1
                    else:
                        diff_srv_count += 1
                    if pkt["IP"].dst == pkt["IP"].src:
                        dst_host_same_src_port_count += 1
                        if pkt["TCP"].dport == pkt["TCP"].sport:
                            dst_host_same_srv_count += 1
                        else:
                            dst_host_diff_srv_count += 1
                        if "error" in str(pkt["TCP"].flags).lower():
                            dst_host_serror_count += 1
                        if "rst" in str(pkt["TCP"].flags).lower():
                            dst_host_rerror_count += 1
                    else:
                        dst_host_srv_diff_host_count += 1
                        if "error" in str(pkt["TCP"].flags).lower():
                            dst_host_srv_serror_count += 1
                        if "rst" in str(pkt["TCP"].flags).lower():
                            dst_host_srv_rerror_count += 1

                    dst_host_count = len(Counter([pkt["IP"].dst]))

            except IndexError:
                # Skip packets that do not contain the expected layers
                continue

        # Calculate rates
        v1 = duration
        v2 = logged_in
        v3 = count
        v4 = serror_count
        v5 = srv_serror_count
        v6 = rerror_count
        v7 = srv_rerror_count
        v8 = same_srv_count
        v9 = diff_srv_count
        v10 = dst_host_count
        v11 = dst_host_srv_count
        v12 = dst_host_same_srv_count
        v13 = dst_host_diff_srv_count
        v14 = dst_host_same_src_port_count
        v15 = dst_host_srv_diff_host_count
        v16 = dst_host_serror_count
        v17 = dst_host_srv_serror_count
        v18 = dst_host_rerror_count
        v19 = dst_host_srv_rerror_count
        print(
            v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19
        )
        # row=[[53.0,1.0,4.0,140.0,2.0,155.0,1.0,3.1,3.0,0.0,7.0]]
        row = [
            [
                v1,
                v2,
                v3,
                v4,
                v5,
                v6,
                v7,
                v8,
                v9,
                v10,
                v11,
                v12,
                v13,
                v14,
                v15,
                v16,
                v17,
                v18,
                v19,
            ]
        ]
        # row=[[0.0,308.0,312.0,0.0,0.0,1.0,0.0,0.0,20.0,20.0,0.0,0.0,0.0,0.0,1.0,0.0,0.0,66.0,255.0,1.0,0.0,0.02,0.02,0.0,0.0,0.0,0.0,1.0,24]]
        yhat = model.predict(row)
        pr = int(yhat)
        return pr

