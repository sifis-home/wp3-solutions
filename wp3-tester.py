"""
Test script for WP3 solutions applications.

The script sends commands to the DHT which triggers the targeted
Client to send a request to its associated Server(s).

The application then checks and prints whether the response
message from the DHT (coming from the Client relaying back
responses) contains the expected information.
"""

import websockets
import asyncio
import json
import re
import sys
from termcolor import colored

async def connect_to_server():
    # URI of the WebSocket server (DHT)
    uri = "ws://localhost:3000/ws"

    async with websockets.connect(uri) as websocket:
        # Define the possible choices for topic for outgoing messages
        outgoingTopics = ["command_dev2", "command_co", "command_ed"]

        # List of topics to filter incoming messages
        incomingTopics = ["output_dev2", "output_co", "output_ed"]

        # Information about possible receivers
        targets = [
            "Group OSCORE Client",
            "CoAP Client",
            "EDHOC Client",
        ]

        # Run tests  for targets 0-2
        tests = [0, 1, 2]

        # Regex patterns for test success
        regex_patterns = [
            "Response #1.*Payload: ON.*Response #2.*Payload: ON.*Response #3.*Payload: ON",
            "Response #1.*UNAUTHORIZED",
            "Response #1.*Payload: Turning on light",
        ]

        # List to store test results
        test_results = []

        print()
        print("Will perform tests for the WP3 solutions applications.")
        print("Sends commands to the DHT and confirms reception of correct message back.")
        print()

        # Loop through and execute tests
        for testNr in tests:

            # Assign selected topic
            topicVal = outgoingTopics[testNr]

            # Use payload on for tests
            msgVal = "on"

            # Build the JSON payload (volatile message)
            payload = {
                    "RequestPubMessage": {
                        "value" :{
                            "message": msgVal,
                            "topic": topicVal
                    }
                }
            }
            json_payload = json.dumps(payload)

            # Send the JSON payload to the server
            await websocket.send(json_payload)

            # Wait for one response or for 5 seconds
            # Only accept responses with correct topic
            response = None
            try:
                print(f"Test {targets[testNr]}: ", end="")

                # Keep receiving messages until timeout or correct topic
                while True:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    if incomingTopics[testNr] in response:
                        # print("Received message from DHT:", response)
                        break

            except asyncio.TimeoutError:
                print(f"{colored('FAIL (timeout)', 'red')}")
                test_results.append(False)

            if response is not None:
                match = re.search(regex_patterns[testNr], response)
                if match:
                    print(f"{colored('PASS', 'green')}")
                    test_results.append(True)
                else:
                    print(f"{colored('FAIL', 'red')}")
                    test_results.append(False)

        # Return exit status
        if all(test_results):
            sys.exit(0)
        else:
            sys.exit(test_results.index(False) + 1)


try:
    asyncio.run(connect_to_server())
except KeyboardInterrupt:
    print("")

