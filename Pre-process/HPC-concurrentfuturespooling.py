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
                

            elif 'HTTP' in c[count] :
                pcapstats["counthttp"]+=1
                try : 
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].http_raw.value + c[count].data_raw.value
                except :
                    byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].http_raw.value
                

            elif 'MDNS' in c[count] :
                pcapstats["countmdns"]+=1
                try :
                    byteValue = c[count].ipv6_raw.value + c[count].udp_raw.value + c[count].mdns_raw.value
                except :
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].mdns_raw.value
                

            elif 'DNS' in c[count] and 'UDP' in c[count] :
                pcapstats["countdns"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].dns_raw.value
                

            elif 'DTLS' in c[count] :
                pcapstats["countdtls"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].dtls_raw.value
                

            elif 'GQUIC' in c[count] :
                pcapstats["countgquic"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].gquic_raw.value
                

            elif 'RTCP' in c[count] :
                pcapstats["countrtcp"]+=1
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].rtcp_raw.value
                

            elif 'STUN' in c[count] :
                pcapstats["countstun"]+=1
                try :
                    c[count].ip_raw.value + c[count].udp_raw.value + c[count].stun_raw.value
                except :
                    try :
                        byteValue = c[count].ip_raw.value + c[count].tcp_raw.value + c[count].stun_raw.value
                    except :
                        byteValue = c[count].ip_raw.value + c[count].stun_raw.value
                

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
                

            elif 'UDP' in c[count] and 'DATA' in c[count] :
                pcapstats["countudp"]+=1
                try :
                    byteValue = c[count].ipv6_raw.value + c[count].udp_raw.value + c[count].data_raw.value
                except : 
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].data_raw.value

 
            elif 'RTCP' in c[count] :
                pcapstats["countrtcp"]+=1
                try:
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].rtcp_raw.value
                except : 
                    byteValue = c[count].ip_raw.value + c[count].udp_raw.value


            else :
                print(c[count].highest_layer)  
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
        # Log the error and print the full traceback
        logging.error("Exception occurred", exc_info=True)

        # Send email if error is detected
        logger.exception(f"Error occured on {cdetails['filename']} at Packet {count+1}")
        print("Error")


# concurrent futures pooling
import concurrent.futures
import time

inputPath = "/home/user/afifhaziq/HPC-ISCX/"
outputPath = "/home/user/afifhaziq/ISCX-Done/"

# Change this for each file
# Utilize it to the max compute capacity
pcaplist = [["voipbuster_4b", ".pcap", "voipbuster"],
            ["voipbuster_4a", ".pcap", "voipbuster"],
            ["skype_video2a", ".pcap", "skypevideo"],
            ["skype_video2b", ".pcapng", "skypevideo"],
            ["skype_audio4", ".pcapng", "skypeaudio"],
            ["skype_audio3", ".pcapng", "skypeaudio"],
            ["facebook_audio3", ".pcapng", "facebookaudio"],
            ["facebook_audio3", ".pcapng", "facebookaudio"]]

cdetails = []

for i in pcaplist:
    detail = {
        "filename": i[0],
        "fileExtension": i[1],
        "label": i[2],
        "input": inputPath + i[0] + i[1],
        "output": outputPath + i[0] + i[1] + '.csv'
    }
    cdetails.append(detail)



if __name__ == '__main__': 
    
    start = time.perf_counter()
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        
        # Map the pcaploop function over the list of dictionaries
        executor.map(pcaploop, cdetails)

    end = time.perf_counter()
    print(f"Time taken: {end - start} seconds")
    
    
    # printing df details
    for i in cdetails:
        print(i["output"])
        

