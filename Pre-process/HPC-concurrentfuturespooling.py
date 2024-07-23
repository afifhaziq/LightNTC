import pyshark
import pandas as pd
import numpy as np
import nest_asyncio
import warnings
import os
warnings.filterwarnings("ignore")
nest_asyncio.apply()


# 2960 because when converting from hex to decimal by 2 digit, the output is reduced to half which is 1480
# 2 digits hex is equivalent to one element in the numpy array/df column
def padding(byteValue) :
    byteValue = byteValue.ljust(2960, '0')
    return byteValue


def processPacket(byteValue) :

    # Process to truncate or padding
    byteLen = len(byteValue)
    if byteLen < 2960 :
        byteValue = padding(byteValue)
        
    byteList = []

    #convert the packet from hexadecimal to decimal format
    for i in range(0, 2960, 2):
        temp = byteValue[i:i+2]
        base16INT = int(temp, 16)
        byteList.append(base16INT)
    return byteList

#send error exception through email and log it
import logging
import logging.handlers

# set up logging to file, rotating log files every 5MB and keep 3 old ones
logging.basicConfig(filename='error.log', 
                    level=logging.ERROR,
                    format='%(asctime)s - %(message)s', 
                    datefmt='%Y-%m-%d %H:%M:%S')

# Email details
smtp_handler = logging.handlers.SMTPHandler(mailhost=('smtp.gmail.com', 587),
                fromaddr="afifhaziq3078@gmail.com",
                toaddrs="afifhaziq3078@gmail.com",
                subject="Pre-Processing error message",
                credentials=("afifhaziq3078@gmail.com", ""),
                secure=())

logger = logging.getLogger()
logger.addHandler(smtp_handler)




pcapstats = {"total": 0,
             "counttls": 0,
             "countdns": 0,
             "counttcp": 0, 
             "countudp": 0,  
             "counthttp": 0,  
             "countmdns": 0,  
             "countdtls": 0,  
             "countstun": 0,  
             "countgquic": 0,  
             "countrtcp": 0}

count = 0
countIndex = 0
checkstring =""
def pcaploop(cdetails):

    processid = os.getpid()
    print("ID of process running: {}".format(processid)) 

    input_file = cdetails["input"]
    label = cdetails["label"]

    c = pyshark.FileCapture(input_file, use_json=True, include_raw=True)
    print("Done Read PCAP")

    countDf = 0
    df = pd.DataFrame()
    while countDf < 1480 :
        index = 'B' + str(countDf)
        df[index] = np.nan
        countDf += 1

    global count 
    global countIndex
    try:
        for packet in c :
            # print progress with PID
            print(f'{count} - PID: {format(processid)} - {cdetails["filename"]}')
            checkstring = str(packet.layers)

            if 'TLS' in packet :
                pcapstats["counttls"]+=1
                try:
                    byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.tls_raw.value
                except:
                    byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.tls_raw.value[0]
                

            elif 'HTTP' in packet :
                pcapstats["counthttp"]+=1
                try : 
                    byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.http_raw.value + packet.data_raw.value
                except :
                    byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.http_raw.value
                

            elif 'MDNS' in packet :
                pcapstats["countmdns"]+=1
                try :
                    byteValue = packet.ipv6_raw.value + packet.udp_raw.value + packet.mdns_raw.value
                except :
                    byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.mdns_raw.value
                

            elif 'DNS' in packet and 'UDP' in packet :
                pcapstats["countdns"]+=1
                byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.dns_raw.value
                

            elif 'DTLS' in packet :
                pcapstats["countdtls"]+=1
                byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.dtls_raw.value
                

            elif 'GQUIC' in packet :
                pcapstats["countgquic"]+=1
                byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.gquic_raw.value
                
            
            elif 'RTCP' in packet or 'RTCP' in checkstring :
                pcapstats["countrtcp"]+=1
                try:
                    byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.rtcp_raw.value
                except : 
                    byteValue = packet.ip_raw.value + packet.udp_raw.value

            elif 'STUN' in packet :
                pcapstats["countstun"]+=1
                try :
                    packet.ip_raw.value + packet.udp_raw.value + packet.stun_raw.value
                except :
                    try :
                        byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.stun_raw.value
                    except :
                        byteValue = packet.ip_raw.value + packet.stun_raw.value
                

            elif 'TCP' in packet :
                if 'DATA' in packet :
                    pcapstats["counthttp"]+=1
                    try :
                        byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.http_raw.value + packet.data_raw.value
                        pcapstats["counthttp"]+=1
                    except :
                        byteValue = packet.ip_raw.value + packet.tcp_raw.value + packet.data_raw.value
                        pcapstats["counttcp"]+=1
                else :
                    pcapstats["counttcp"]+=1
                    byteValue = packet.ip_raw.value + packet.tcp_raw.value
                

            elif 'UDP' in packet and 'DATA' in packet :
                pcapstats["countudp"]+=1
                try :
                    byteValue = packet.ipv6_raw.value + packet.udp_raw.value + packet.data_raw.value
                except : 
                    byteValue = packet.ip_raw.value + packet.udp_raw.value + packet.data_raw.value

            else :
                print(packet.highest_layer)  
                count +=1
                continue

            count += 1
            df.loc[countIndex] = processPacket(byteValue)
            countIndex += 1

        # Assign label when the loop is completed 
        df['label'] = label

        print('Done')
        print('Total packets inspected:', count)
        print('Total packets extracted:',pcapstats["counttls"] + pcapstats["countdns"] + pcapstats["counttcp"] + pcapstats["countudp"] + pcapstats["counthttp"] + pcapstats["countmdns"] + pcapstats["countdtls"] + pcapstats["countstun"] + pcapstats["countgquic"] + pcapstats["countrtcp"])
        print(pcapstats)

        df.to_csv(cdetails["output"], index=False)
        print(cdetails["output"])

    except Exception as e:

        # Send email if error is detected
        logger.exception(f"Error occured on {cdetails['filename']} at Packet {count+1}")
        print("Error")


# concurrent futures pooling
import concurrent.futures
import time
import json

# inputPath = "/scr/user/afifhaziq/HPC-ISCX/"
# outputPath = "/home/project/csnet/ISCX-Done/"

inputPath = "C:\\Users\\afif\\Documents\\Master\\Code\\Dataset\\Done-03\\"
outputPath = "C:\\Users\\afif\\Documents\\Master\\Code\\Dataset\\test\\"

def load_pcap_list(filename):
    with open(filename, 'r') as file:
        pcaplist = json.load(file)
        cdetails = []

        # Create a list of PCAP dictionary based on the pcaplist
        for i in pcaplist:
            detail = {
                "filename": i[0],
                "fileExtension": i[1],
                "label": i[2],
                "input": inputPath + i[0] + i[1],
                "output": outputPath + i[0] + i[1] + '.csv'
            }
            cdetails.append(detail)
    return cdetails



if __name__ == '__main__': 
    
    start = time.perf_counter()
    
    cdetails = load_pcap_list('pcaplist.json')
    with concurrent.futures.ProcessPoolExecutor() as executor:
        
        # Map the pcaploop function over the list of dictionaries
        executor.map(pcaploop, cdetails)

    end = time.perf_counter()
    print(f"Time taken: {end - start} seconds")
    
    # printing df details
    for i in cdetails:
        print(i["output"])
        

