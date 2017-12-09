# STP
## simple transport protocol
## implement a reliable transport protocol over UDP protocol.
### this code only can run on the python 3.6 or higher version.

* the input at sender port should like:
    python sender.py receiver_host_ip receiver_port file.txt MWS MSS timeout pdrop seed
* the input at receiver port should like:
    python receiver.py receiver_port file.txt
* the header is designed like this:

|source IP source port|destination IP destination port|sequence|acknowledge|SYN|FIN|MSS|MWS|data length|DATA payload|
|:-----------:|:----------------:|:--------:|:-----------:|:-----:|:-----:|:-----:|:-----:|:------:|:-----:|

- after runing the reciver.py, the sender.py should be run.
- after runing those code, there are 2 generated files, 'Receiver_log.txt' and 'Sender_log.txt'. the data consist of several parts.

|send/recieve|time|type of packet|seqence number|number of bytes|acknowledge number|
|:-----------|:--:|:------------:|:------------:|:-------------:|:----------------:|