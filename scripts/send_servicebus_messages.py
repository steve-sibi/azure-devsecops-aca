#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from azure.servicebus import ServiceBusClient, ServiceBusMessage


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_metadata(value: str) -> dict:
    if not value:
        return {}
    try:
        doc = json.loads(value)
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid --metadata JSON: {e}") from e
    if not isinstance(doc, dict):
        raise SystemExit("--metadata must be a JSON object")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enqueue scan messages to an Azure Service Bus queue. Intended for KEDA scale tests."
        )
    )
    parser.add_argument(
        "--connection-string",
        default=os.getenv("SERVICEBUS_CONN", ""),
        help="Service Bus connection string (or set SERVICEBUS_CONN).",
    )
    parser.add_argument("--queue", required=True, help="Queue name (e.g. tasks).")
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of messages to send (default: 50).",
    )
    parser.add_argument(
        "--url",
        default="https://example.com",
        help="HTTPS URL to scan (default: https://example.com).",
    )
    parser.add_argument(
        "--type",
        default="url",
        help="Scan type field (default: url).",
    )
    parser.add_argument(
        "--source",
        default="keda-scale-test",
        help="Source field for messages (default: keda-scale-test).",
    )
    parser.add_argument(
        "--metadata",
        default="",
        help='Optional JSON object string for "metadata" (default: empty).',
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Send messages in batches of this size (default: 50).",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=900,
        help="Message TTL in seconds (default: 900).",
    )
    args = parser.parse_args()

    if not args.connection_string:
        raise SystemExit(
            "Missing --connection-string (or set SERVICEBUS_CONN environment variable)."
        )
    if args.count <= 0:
        raise SystemExit("--count must be > 0")
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be > 0")

    metadata = _parse_metadata(args.metadata)
    ttl = timedelta(seconds=args.ttl_seconds) if args.ttl_seconds > 0 else None

    sent = 0
    with ServiceBusClient.from_connection_string(args.connection_string) as client:
        with client.get_queue_sender(queue_name=args.queue) as sender:
            while sent < args.count:
                batch_n = min(args.batch_size, args.count - sent)
                messages: list[ServiceBusMessage] = []
                for _ in range(batch_n):
                    job_id = str(uuid4())
                    correlation_id = str(uuid4())
                    payload = {
                        "job_id": job_id,
                        "correlation_id": correlation_id,
                        "url": args.url,
                        "type": args.type,
                        "source": args.source,
                        "metadata": metadata,
                        "submitted_at": _utc_now_iso(),
                    }
                    msg = ServiceBusMessage(
                        json.dumps(payload),
                        content_type="application/json",
                        message_id=job_id,
                        application_properties={
                            "schema": "scan-v1",
                            "correlation_id": correlation_id,
                            "source": args.source,
                            "keda_scale_test": True,
                        },
                    )
                    if ttl is not None:
                        try:
                            msg.time_to_live = ttl
                        except Exception:
                            pass
                    messages.append(msg)

                sender.send_messages(messages)
                sent += batch_n
                print(f"Sent {sent}/{args.count} messages...", flush=True)

    print(f"Done. Enqueued {sent} messages to queue={args.queue}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

