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

def truncate(byteValue) :
    byteValue = byteValue[0:2960]
    return byteValue

def processPacket(byteValue) :

    # Process to truncate or padding
    byteLen = len(byteValue)
    if byteLen > 2960 :
        byteValue = truncate(byteValue)
    else:
        byteValue = padding(byteValue)
        
    byteList = []

    #convert the packet from hexadecimal to decimal format
    for i in range(0, len(byteValue), 2):
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
                credentials=("afifhaziq3078@gmail.com", "yfxiwaukimuhgdvn"),
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
def pcaploop(cdetails):

    processid = os.getpid()
    print("ID of process running: {}".format(processid)) 

    input_file = cdetails["input"]
    label = cdetails["label"]

    c = pyshark.FileCapture(input_file, use_json=True, include_raw=True)
    print("Done Read PCAP")

    countDf = 0
    df = pd.DataFrame()
    while countDf <= 1479 :
        index = 'B' + str(countDf)
        df[index] = np.nan
        countDf += 1

    global count 
    global countIndex
    try:
        for x in c :
            # print progress with PID
            print(f'{count} - PID: {format(processid)} - {cdetails["filename"]}')
            if 'TLS' in c[count] :
                pcapstats["counttls"]+=1
                try:
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].tls_raw.value
                except:
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].tls_raw.value[0]
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'HTTP' in c[count] :
                pcapstats["counthttp"]+=1
                try : 
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].http_raw.value + c[count].data_raw.value
                except :
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].http_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'MDNS' in c[count] :
                pcapstats["countmdns"]+=1
                try :
                    byteValue = c[count].ipv6_raw.value + c[count].udp_raw.value + c[count].mdns_raw.value
                except :
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].mdns_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'DNS' in c[count] and 'UDP' in c[count] :
                pcapstats["countdns"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].dns_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'DTLS' in c[count] :
                pcapstats["countdtls"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].dtls_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'GQUIC' in c[count] :
                pcapstats["countgquic"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].gquic_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'RTCP' in c[count] :
                pcapstats["countrtcp"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].rtcp_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'STUN' in c[count] :
                pcapstats["countstun"]+=1
                try :
                    c[count].ip_raw.value + c[count].udp_raw.value + c[count].stun_raw.value
                except :
                    try :
                        byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].stun_raw.value
                    except :
                        byteValue = c[count].ip_raw.value + c[count].stun_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'TCP' in c[count] :
                #print('TCP')
                if 'DATA' in c[count] :
                    pcapstats["counthttp"]+=1
                    try :
                        byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].http_raw.value + c[count].data_raw.value
                        pcapstats["counthttp"]+=1
                    except :
                        byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].data_raw.value
                        pcapstats["counttcp"]+=1
                else :
                    pcapstats["counttcp"]+=1
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'UDP' in c[count] and 'DATA' in c[count] :
                pcapstats["countudp"]+=1
                try :
                    byteValue = c[count].ipv6_raw.value + c[count].udp_raw.value + c[count].data_raw.value
                except : 
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].data_raw.value

                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            elif 'RTCP' in c[count] :
                pcapstats["countrtcp"]+=1
                try:
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].rtcp_raw.value
                except : 
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value

                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1

            else :
                print(c[count].highest_layer)  
            count += 1
            
        df['label'] = label

        print('Done')
        print('Total packets inspected:', count)
        print('Total packets extracted:',pcapstats["counttls"] + pcapstats["countdns"] + pcapstats["counttcp"] + pcapstats["countudp"] + pcapstats["counthttp"] + pcapstats["countmdns"] + pcapstats["countdtls"] + pcapstats["countstun"] + pcapstats["countgquic"] + pcapstats["countrtcp"])
        print(pcapstats)

        df.to_csv(cdetails["output"], index=False)
        print(cdetails["output"])

    except Exception as e:
        # Log the error and print the full traceback
        logging.error("Exception occurred", exc_info=True)

        # Send email if error is detected
        logger.exception(f"Error occured on {c1details['filename']} at Packet {count+1}")
        print("Error")


# concurrent futures pooling
import concurrent.futures
import time

inputPath = "/home/user/afifhaziq/HPC-ISCX/"
outputPath = "/home/user/afifhaziq/ISCX-Done/"

c1details = {"filename": "voipbuster_4b",
             "fileExtension" : ".pcap",
             "label" : "voipbuster"}
c1details["input"] = inputPath + c1details["filename"] + c1details["fileExtension"]
c1details["output"] = outputPath + c1details["filename"] + c1details["fileExtension"] + '.csv'

c2details = {"filename": "voipbuster_4a",
             "fileExtension" : ".pcap",
             "label" : "voipbuster"}
c2details["input"] = inputPath + c2details["filename"] + c2details["fileExtension"]
c2details["output"] = outputPath + c2details["filename"] + c2details["fileExtension"] + '.csv'

c3details = {"filename": "skype_video2a",
             "fileExtension" : ".pcap",
             "label" : "skypevideo"}
c3details["input"] = inputPath + c3details["filename"] + c3details["fileExtension"]
c3details["output"] = outputPath + c3details["filename"] + c3details["fileExtension"] + '.csv'

c4details = {"filename": "skype_video2b",
             "fileExtension" : ".pcapng",
             "label" : "skypevideo"}
c4details["input"] = inputPath + c4details["filename"] + c4details["fileExtension"]
c4details["output"] = outputPath + c4details["filename"] + c4details["fileExtension"] + '.csv'


if __name__ == '__main__': 
    
    start = time.perf_counter()
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        
        # Map the pcaploop function over the list of dictionaries
        executor.map(pcaploop, [c1details, c2details, c3details, c4details])


    
    end = time.perf_counter()
    print(f"Time taken: {end - start} seconds")
    
    # printing df details
    print(c1details["output"])
    print(c2details["output"])
    print(c3details["output"])
    print(c4details["output"])

