"""
Application that sends a command to the DHT which triggers the
targeted Client to send a request to its associated Server(s).

The application then prints the response message from the DHT coming
from the Client relaying back responses from its associated Server(s).
"""

import websockets
import asyncio
import json

async def connect_to_server():
    # URI of the WebSocket server (DHT)
    uri = "ws://localhost:3000/ws"

    async with websockets.connect(uri) as websocket:
        # Define the possible choices for topic for outgoing messages
        outgoingTopics = ["command_dev1", "command_dev2", "command_co", "command_ed"]

        # Information about possible receivers
        targets = [
            "Group OSCORE Client #1",
            "Group OSCORE Client #2",
            "CoAP Client",
            "EDHOC Client",
        ]

        # Print the possible choices
        for i, option in enumerate(targets):
            print(f"{i + 1}. {option}")

        # Prompt the user to choose a value for topic
        topicSel = input("Enter device to send to: ")

        # Assign selected topic
        topicSelInt = int(topicSel) - 1
        topicVal = outgoingTopics[topicSelInt]

        # Ask user to provide payload value
        msgVal = input("Enter payload to send: ")

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

        # List of topics to filter incoming messages
        incomingTopics = ["output_dev1", "output_dev2", "output_co", "output_ed"]

        # Wait for one response from the server
        # Only accept responses with correct topic
        while True:
            response = await websocket.recv()

            if incomingTopics[topicSelInt] in response:
                print("Received message from DHT:", response)
                break


# Actually run the code

try:
    asyncio.run(connect_to_server())
except KeyboardInterrupt:
    print("")

