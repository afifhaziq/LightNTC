# LightNTC

## Pre-Processing ISCX - Raw Byte
by: @mebikarbonat

Dataset Link: a <http://205.174.165.80/CICDataset/ISCX-VPN-NonVPN-2016/Dataset/>

## Pre-training Process - Part 1

Change the following variable on the ISCX-VPN2016-pre-processing-v2.ipynb
- Input Path: .PCAP/.PCAPNG File directory on the local machine
- Output Path: File directory for output processed .PCAP
- filename: Name of the .pcap file
- file extension: .PCAP / .PCAPNG
- label: The application class from the dataset
- batch: batch can be set to limit the number of packets processed in one run.

Note: 
- For a large .PCAP, set batch to smaller batch, then run the cell below the variable initialization until it fully covers the whole file.
- The number of packets left to be processed can be referred in the same cell once the first batch has been completely processed.


### Summary for ISCX-VPN2016-pre-processing-v2.ipynb
- Set .PCAP and PCAPNG file as input and save the file as .CSV
- .PCAP will read as JSON from the FileCapture class when read from the file directory to speed up the process.
- Create an empty df with 1480 columns representing MTU.
- The number of rows will represent the number of packets.
- Each of the packets will be padding/truncated to 1480 bytes
- Packets will be filtered based on 10 protocol
- byteValue variable is a summation of the respective protocol-related raw bytes.
- Once filtered, the packet will undergo padding/truncating via processPacket function with parameter byteValue
- The raw bytes will be converted from hex to decimal and appended to the df for the respective byte
- Save the file as .CSV

### Summary for output .CSV file
- each of the features is included in column A and separated by a comma
- Label is included as the last element in the cell
