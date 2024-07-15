
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
    elif byteLen < 2960 :
        byteValue = padding(byteValue)
        
    n = 2
    byteList = []

    #convert the packet from hexadecimal to decimal format
    for i in range(0, len(byteValue), n):
        temp = byteValue[i:i+n]
        base16INT = int(temp, 16)
        byteList.append(base16INT)
    return byteList

#send error exception through email
import logging
import logging.handlers

# Email details
smtp_handler = logging.handlers.SMTPHandler(mailhost=('smtp.gmail.com', 587),
                fromaddr="afifhaziq3078@gmail.com",
                toaddrs="afifhaziq3078@gmail.com",
                subject="Pre-Processing error message",
                credentials=("afifhaziq3078@gmail.com", "<password>"),
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
            print(f"{count} - PID: {format(processid)}")
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
                byteValue = c[count].ip_raw.value + c[count].udp_raw.value + c[count].rtcp_raw.value
                df.loc[countIndex] = processPacket(byteValue)
                countIndex += 1
                pcapstats["countrtcp"]+=1
                print('RTCP')

            else :
                print(c[count].highest_layer)  
            count += 1
            
        df['label'] = label

        print('Done')
        print('Total packets inspected:', count)
        print('Total packets extracted:',pcapstats["counttls"] + pcapstats["countdns"] + pcapstats["counttcp"] + pcapstats["countudp"] + pcapstats["counthttp"] + pcapstats["countmdns"] + pcapstats["countdtls"] + pcapstats["countstun"] + pcapstats["countgquic"] + pcapstats["countrtcp"])
        print(pcapstats)

    except Exception as e:
        logger.exception('Unhandled Exception')
        print("Error")

    return df

# Multiprocessing pooling
import concurrent.futures
import pandas as pd
import time

inputPath = "C:\\Users\\afif\\Documents\\Master\\Code\\Dataset\\test\\"
outputPath = "C:\\Users\\afif\\Documents\\Master\\Code\\Dataset\\test\\"

c1details = {"filename": "scpUp3",
             "fileExtension" : ".pcap",
             "label" : "scp",
             "input" : inputPath + "scpUp3" + ".pcap"}

c2details = {"filename": "scpDown4",
             "fileExtension" : ".pcap",
             "label" : "scp",
             "input" : inputPath + "scpDown4" + ".pcap"}



if __name__ == '__main__': 
    
    start = time.perf_counter()
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        
        # Map the pcaploop function over the list of dictionaries
        result1 = executor.map(pcaploop, [c1details, c2details])


    # Concatenate all DataFrames into a single DataFrame
    # df1 = pd.concat(results1, ignore_index=True)

    df1, df2 = result1
    end = time.perf_counter()
    print(f"Time taken: {end - start} seconds")
    
    print(df1)
    print(df2)

    # Save the file in csv
    # output1 = outputPath + c1details["filename"] + c1details["fileExtension"] + '.csv'
    # df1.to_csv(output1, index=False)
    # print(output1)

    # output2 = outputPath + c2details["filename"] + c2details["fileExtension"] + '.csv'
    # df2.to_csv(output2, index=False)
    # print(output2)