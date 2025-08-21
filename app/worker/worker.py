import json
import logging
import os
import signal
import time
from typing import List

from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError

# ---- Config via env ----
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_WAIT = int(os.getenv("MAX_WAIT", "5"))  # seconds
PREFETCH = int(os.getenv("PREFETCH", "20"))
MAX_RETRIES = int(
    os.getenv("MAX_RETRIES", "5")
)  # move to DLQ after this many deliveries
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional (opencensus)

# ---- Logging (console + optional App Insights) ----
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
if APPINSIGHTS_CONN:
    try:
        from opencensus.ext.azure.log_exporter import AzureLogHandler

        logging.getLogger().addHandler(
            AzureLogHandler(connection_string=APPINSIGHTS_CONN)
        )
    except Exception as e:
        logging.warning(f"App Insights logging not enabled: {e}")

shutdown = False


def _signal_handler(*_):
    global shutdown
    shutdown = True


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


def _decode_body(msg) -> dict:
    # msg.body is an iterable of bytes/memoryview sections; join & decode
    body_bytes = b"".join(
        bytes(b) if isinstance(b, memoryview) else b for b in msg.body
    )
    return json.loads(body_bytes.decode("utf-8"))


def process(task: dict):
    # TODO: replace with real work
    logging.info(f"[worker] Processing: {task}")
    time.sleep(1)


def main():
    if not SERVICEBUS_CONN:
        raise RuntimeError("SERVICEBUS_CONN env var is required")

    client = ServiceBusClient.from_connection_string(
        SERVICEBUS_CONN, logging_enable=True
    )
    logging.info("[worker] started; waiting for messages...")

    with client:
        receiver = client.get_queue_receiver(
            queue_name=QUEUE_NAME,
            max_wait_time=MAX_WAIT,
            prefetch_count=PREFETCH,
        )
        with receiver:
            while not shutdown:
                try:
                    messages = receiver.receive_messages(
                        max_message_count=BATCH_SIZE,
                        max_wait_time=MAX_WAIT,
                    )
                    if not messages:
                        continue

                    for msg in messages:
                        try:
                            task = _decode_body(msg)
                            process(task)
                            receiver.complete_message(msg)
                        except Exception as e:
                            # DLQ if too many deliveries, else make it available again
                            if msg.delivery_count >= MAX_RETRIES:
                                receiver.dead_letter_message(
                                    msg,
                                    reason="max-retries-exceeded",
                                    error_description=str(e),
                                )
                                logging.error(f"[worker] DLQ'd message: {e}")
                            else:
                                receiver.abandon_message(msg)
                                logging.warning(
                                    f"[worker] Abandoned message (retry {msg.delivery_count}): {e}"
                                )
                except OperationTimeoutError:
                    # no messages within wait window
                    continue
                except ServiceBusError as e:
                    logging.error(f"[worker] ServiceBusError: {e}")
                    time.sleep(2)  # brief backoff

    logging.info("[worker] shutdown complete.")


if __name__ == "__main__":
    main()
