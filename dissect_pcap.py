import dpkt
import struct
import glob
import pandas as pd
from datetime import datetime
import itertools

# iNETx structure:
# • iNET control field (32 bits): 4 bytes
# • Stream ID (32 bits): 4 bytes
# • Sequence Number (32 bits): 4 bytes
# • Packet length Field (32 bits): 4 bytes
# • PTP Timestamp (64 bits): 8 bytes
# • iNET-X Payload Information field (32 bits): 4 bytes
# •   Error/Event Code (16 bits): 2 bytes
# •   Parameter (16 bits) 2 bytes - This is the value of the mode to which the KAD/BCU/140/F/SEF module should be switched


def ptp_timestamp_calc(inetx):
    ptp_timestamp_seconds_hex = int(inetx[16:20].hex().upper(), 16)
    ptp_timestamp_nanoseconds_hex = int(inetx[20:24].hex().upper(), 16)
    ptp_timestamp_seconds = ptp_timestamp_seconds_hex + (ptp_timestamp_nanoseconds_hex/1000000000)
    ptp_timestamp = datetime.utcfromtimestamp(ptp_timestamp_seconds).strftime('%H:%M:%S.%f')
    return ptp_timestamp

def bytes2binstr(b, n=None):
    s = ' '.join(f'{x:08b}' for x in b)
    return s if n is None else s[:n + n // 8 + (0 if n % 8 else -1)]

def get_payload_bytes(payload_content):
    for payload_bytes in payload_content:
        return [payload_content[0::, 2]]


#Only iNET-X packets coming from the IP addresses i this list will be checked
#src_ip_addresses_to_check = ['192.168.28.12', '192.168.28.11', '192.168.28.13', '192.168.28.15',
#                            '192.168.28.17', '192.168.28.10', '192.168.28.14', '192.168.28.16',
#                             '192.168.28.18', '192.168.28.1', '192.168.28.20']

src_ip_addresses_to_check = ['192.168.28.12']

pcap_file_list = glob.glob('_ethernet_*')
pcap_count = 1

print(f'\nAnalysing iNET-X packets coming from IP address: {src_ip_addresses_to_check[0]}')
df = pd.DataFrame()
streamid_list = []
timestamp_list = []
for pcap_file in pcap_file_list:
    print('\nAnalysing {}. File {} or {}'.format(pcap_file, pcap_count, len(pcap_file_list)))
    print('-'*50)
    pcap_count += 1

    # --------------------------------------------------------------------------
    print('Extracting the inetx content, please wait. \n')

    ethernet_data = dpkt.pcap.Reader(open(pcap_file, 'rb'))
    for eth_ts, buf in ethernet_data:

        src_ip_raw = buf[26:30]
        src_ip = '{}.{}.{}.{}'.format(src_ip_raw[0], src_ip_raw[1], src_ip_raw[2], src_ip_raw[3])
        if src_ip in src_ip_addresses_to_check:
                #start_pc_time = datetime.utcfromtimestamp(int(eth_ts)).strftime('%Y-%m-%d %H:%M:%S')

            inetx = buf[42:]
            if inetx[:4] == b'\x11\x00\x00\x00': # The control field is correct
                streamid = inetx[4:8].hex().upper()
                sequence_number = int(inetx[8:12].hex().upper(), 16)
                packet_length = int(inetx[12:16].hex().upper(), 16)
                ptp_timestamp = ptp_timestamp_calc(inetx)
                payload_info_field = bytes2binstr(inetx[24:28])
                error_bit = int(payload_info_field[0])
                lost_count = payload_info_field[1:5]
                timeout = payload_info_field[5]
                payload = (inetx[28::].hex().upper())
                payload_bytes = [payload[i:i+4] for i in range(0, len(payload), 4) ]
                columns=['bytes_' + str(i) + '_' + str(i+1) for i in range(1, 2*len(payload_bytes), 2)]
                streamid_list.append(streamid)
                timestamp_list.append(ptp_timestamp)


            p = pd.DataFrame([streamid_list, timestamp_list])
            p.to_csv('prova.csv')

print('DONE')
                #df = pd.DataFrame([payload_bytes], columns = columns)


                #print(payload, '\n\n\n',  payload_bytes)


                #payload = itertools.islice(inetx[28::].hex(), 0 , None, 2)
                #print(streamid, '\t\t', sequence_number,'\t\t', packet_length, '\t\t', payload)


