import json
import os
import time

from azure.servicebus import ServiceBusClient

SERVICEBUS_CONN = os.environ["SERVICEBUS_CONN"]
QUEUE_NAME = os.environ.get("QUEUE_NAME", "tasks")

client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN, logging_enable=True)


def process(body: str):
    data = json.loads(body)
    print(f"[worker] Processing: {data}")
    time.sleep(1)


print("[worker] started; waiting for messages...")
with client:
    receiver = client.get_queue_receiver(queue_name=QUEUE_NAME)
    for msg in receiver:
        try:
            process(str(msg))
            receiver.complete_message(msg)
        except Exception as e:
            receiver.abandon_message(msg)
            print(f"[worker] error: {e}")
