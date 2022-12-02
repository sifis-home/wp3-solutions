
**Codebase for SIFIS-HOME including OSCORE, Group OSCORE, ACE and Group Joining.**

To setup and run the provided applications, follow the steps below. This will start 3 clients and 1 server in one group, and 3 clients and 1 server in another group. The servers and clients all start by first requesting an ACE Token from the Authorization Server, then posting it to the Group Manager and performing the group join procedure. After that they are ready to securely communicate with Group OSCORE in the group. The clients can be triggered to send requests by sending a message to the SIFIS-Home DHT. The clients will received this command using WebSockets from the DHT.

**Start the Group Manager**  
OscoreRsServer

**Next start the Authorization Server**  
OscoreAsServer

**Now start the server applications:**  
OscoreAsRsClient -name Server1  
OscoreAsRsClient -name Server2  
OscoreAsRsClient -name Server3  
OscoreAsRsClient -name Server4  
OscoreAsRsClient -name Server5  
OscoreAsRsClient -name Server6  

**Start up the SIFIS-Home DHT application**

**Next, start the first client. It will listen to commands from the DHT.**  
OscoreAsRsClient -dht -name Client1

**Then start the second client. It will listen to commands from the DHT.**  
OscoreAsRsClient -dht -name Client2

**Use the following interactive script to send commands to the DHT (and trigger the clients)**  
python3 dht_rest_client.py

**Relevant documentation**  
https://datatracker.ietf.org/doc/rfc8613/  
https://datatracker.ietf.org/doc/rfc9200/  
https://datatracker.ietf.org/doc/draft-ietf-core-oscore-groupcomm/  
https://datatracker.ietf.org/doc/draft-ietf-ace-key-groupcomm-oscore/
