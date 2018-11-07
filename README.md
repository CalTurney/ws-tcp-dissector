# ws-tcp-dissector
This repo provides a means for Wireshark core developers to review proposed changes to the TCP dissector.  I have supplied the source code of the original and updated versions of packet-tcp.c/.h, example captures depicting each feature, a profile that displays useful columns, and a colorfilters file with entries for the added fields.    

I added the several features to the TCP dissector in 'WS-1.5.1 SVN-35980' for my network analysis group at Dell-EMC none of which have been submitted for public distribution.  The most important features follows: 

o   Accurate identification of TCP retransmission types:  “RTO” (RFC 793); “FAST” - Fast Retransmit/Recovery per Tahoe and Reno (RFC2581); “SACK” (RFC2018); “DSACK” (RFC3708); “FACK” (SACK+FACK proposed by Mathis and implemented in most TCP inplementations); “NewReno” (RFC3782); and “Unwarranted”. Retransmissions triggered by SACK, DSACK, FACK, and NewReno are not identified and displayed as such in current versions. 

o  Reliable identification of segments and ACKs as Out-Of-Order (OOO) versus retransmissions:  Packets have been mislabelled as OOO when they were actually retransmissions and vice versa since Ethereal was released and I don't believe OOO ACKs have been employed to differentiate them.  

o  Detailed SACK Info:  I have a capture with 215 outstanding gaps in the byte stream of a single connection. Wireshark does not inform the user of the number, boundaries, and sizes of outstanding gaps. The TCP options field can only hold a maximum of five SACK blocks so the receiver must maintain a list of SACKed blocks. Wireshark must do the same and display this info. We have found that the ability to examine this info can be very helpful in the determination of possible causes of packet loss.   

o  Fixed Congestion Point Analysis (FCPA):  This statistical tool calculates the average number of bytes that were outstanding (unACKed) when the first retransmission of each packet loss event arrived. The tool is useful in cases where receiver’s window size is larger than the number of bytes/frames the network can store before they can be forwarded. For example, the receiver’s window is set to 64 KB and on average 48 KB with a STDEV of 2KB were outstanding when the first retransmission of each recovery event occurred.  In this case we would recommend that the receiver’s window be reduced to 46KB. If throughput improves but remains below the customer’s requirements we determine the point(s) in the path where packets loss is occurring and recommend such things as load balancing, the addition of memory to devicesd in the path, and the reconfiguration of the QoS (priority) scheme.

NOTE: An FCPA is only conducted if the data sender's flow of a given connection resides in a capture that was taken on or near the sender. Data origination is automatically detected but can be manually set as well.

My group has used this version for the analysis of packet loss and evidence of protocol violations in TCP implementations for more than three years. I have not received a bug report in the past 2.5 years; however, I need to fix a bug I found where in a certain scenario an OOO packet is mistakenly labelled as "Unwarrented". In addition, two minor enhancements and a fix of a minor bug need to be added.  

Do these changes increase dissection latency?  I compared the latency between the original and updated versions and found very little difference. If needed, I can substantiate this finding statistically.
 
