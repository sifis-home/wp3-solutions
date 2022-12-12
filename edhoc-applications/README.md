**Codebase for SIFIS-HOME including applications using EDHOC and the optimized request solution.**

To setup and run the provided applications, follow the steps below. This will start 1 EDHOC client acting as initiator and 1 EDHOC server acting as responder. The applications support 4 different configuration alternatives (depending on which client and server is launched). Regardless of the option chosen, the client will execute EDHOC, and as its first OSCORE request sent trigger the server to turn on the light. Follow-up requests are then handled by sending messages to the DHT via the provided Python script.

**Configurations** 
The 4 supported configurations are as follows:  
1. Method 0. Optimized request: False.
2. Method 3. Optimized request: False.
3. Method 0. Optimized request: True.
4. Method 3. Optimized request: True.

**First start the EDHOC Server**  
PhaseXServer  

**Next start up the SIFIS-Home DHT application**  

**Now start the EDHOC Client. It will listen to commands from the DHT.**  
PhaseXClient -dht  

**Use the following interactive script to send commands to the DHT (and trigger the client)**  
python3 dht_rest_client.py  

**Relevant documentation**  
https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/  
https://datatracker.ietf.org/doc/draft-ietf-core-oscore-edhoc/  
