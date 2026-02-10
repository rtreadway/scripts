#!/usr/bin/env python3
"""Utility to send synthetic TAQT SQS messages."""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from jsonschema import Draft7Validator, FormatChecker, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROPERTIES_PATH = PROJECT_ROOT / "src/main/resources/taqt.properties"

OUTER_SCHEMA: Dict[str, object] = {
    "type": "object",
    "required": ["MessageId", "Timestamp", "Message"],
    "properties": {
        "MessageId": {"type": "string", "minLength": 1},
        "Timestamp": {"type": "string", "format": "date-time"},
        "Message": {"type": "string", "minLength": 1},
    },
}

INNER_SCHEMA: Dict[str, object] = {
    "type": "object",
    "required": ["Records"],
    "properties": {
        "Records": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "items": {
                "type": "object",
                "required": ["s3"],
                "properties": {
                    "s3": {
                        "type": "object",
                        "required": ["bucket", "object"],
                        "properties": {
                            "bucket": {
                                "type": "object",
                                "required": ["name", "arn"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "arn": {"type": "string", "pattern": r"^arn:aws:s3:::[^\s]+$"},
                                },
                            },
                            "object": {
                                "type": "object",
                                "required": ["key"],
                                "properties": {
                                    "key": {"type": "string", "minLength": 1},
                                },
                            },
                        },
                    }
                },
            },
        }
    },
}

SCHEMA_VALIDATOR = Draft7Validator(OUTER_SCHEMA, format_checker=FormatChecker())
INNER_VALIDATOR = Draft7Validator(INNER_SCHEMA)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send a synthetic TAQT SQS message that points TAQT to an APACIF file. "
            "The script auto-derives queue URL, bucket name, and bucket ARN from the environment."
        )
    )
    parser.add_argument("--env", choices=["OAT", "PROD"], required=True, help="Environment to emulate.")
    parser.add_argument("--apacif-key", required=True, help="Object key of the APACIF file in the inbound bucket.")
    timing_group = parser.add_mutually_exclusive_group(required=True)
    timing_group.add_argument("--weekend", action="store_true", help="Mark the message as a recent Friday/Saturday drop.")
    timing_group.add_argument("--weekday", action="store_true", help="Mark the message as a recent weekday drop.")
    parser.add_argument("--timestamp", help="ISO-8601 timestamp override (UTC).")
    parser.add_argument("--bucket-name", help="Override the inferred S3 bucket name.")
    parser.add_argument("--bucket-arn", help="Override the inferred S3 bucket ARN.")
    parser.add_argument("--queue-url", help="Override the queue URL instead of using taqt.properties.")
    parser.add_argument("--properties-file", default=str(DEFAULT_PROPERTIES_PATH), help="Path to taqt.properties.")
    parser.add_argument("--profile", help="AWS profile name.")
    parser.add_argument("--region", default="us-east-1", help="AWS region for the SQS client.")
    parser.add_argument("--dry-run", action="store_true", help="Print the payload instead of sending it.")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    return parser.parse_args()


def load_properties(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"')
    return data


def resolve_queue_url(env: str, props: Dict[str, str], override: Optional[str]) -> str:
    if override:
        return override
    key = f"sqsURL{env.upper()}"
    if key not in props or not props[key]:
        raise ValueError(f"Queue URL for {env} not found in taqt.properties (missing key {key}).")
    return props[key]


def derive_bucket_info(env: str, name_override: Optional[str], arn_override: Optional[str]) -> Tuple[str, str]:
    if name_override:
        bucket_name = name_override
    else:
        bucket_name = f"{env.lower()}-inbound-vendor-apex"
    if arn_override:
        bucket_arn = arn_override
    else:
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return bucket_name, bucket_arn


def choose_timestamp(args: argparse.Namespace) -> str:
    if args.timestamp:
        return args.timestamp

    if args.weekend:
        preferred_days = (5, 4)  # Saturday, Friday
    else:
        preferred_days = (2, 3, 1, 0)  # Wednesday, Thursday, Tuesday, Monday

    now = datetime.now(timezone.utc)
    for delta in range(1, 8):
        candidate = now - timedelta(days=delta)
        if candidate.weekday() in preferred_days:
            chosen = candidate.replace(hour=12, minute=0, second=0, microsecond=0)
            return chosen.isoformat().replace("+00:00", "Z")

    raise RuntimeError("Unable to compute a recent timestamp; please provide --timestamp manually.")


def build_payload(bucket_name: str, bucket_arn: str, object_key: str, timestamp: str) -> Dict[str, str]:
    inner = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": bucket_name, "arn": bucket_arn},
                    "object": {"key": object_key},
                }
            }
        ]
    }
    envelope = {
        "MessageId": str(uuid4()),
        "Timestamp": timestamp,
        "Message": json.dumps(inner, separators=(",", ":")),
    }
    return envelope


def validate_payload(envelope: Dict[str, str]) -> None:
    try:
        SCHEMA_VALIDATOR.validate(envelope)
        INNER_VALIDATOR.validate(json.loads(envelope["Message"]))
    except ValidationError as exc:
        raise ValueError(f"Payload validation failed: {exc.message}") from exc


def confirm_send(skip_prompt: bool, queue_url: str) -> bool:
    if skip_prompt:
        return True
    prompt = f"Send message to {queue_url}? [y/N]: "
    try:
        choice = input(prompt).strip().lower()
    except KeyboardInterrupt:
        print()  # newline after Ctrl+C
        return False
    return choice == "y"


def send_message(envelope: Dict[str, str], queue_url: str, args: argparse.Namespace) -> None:
    session_kwargs: Dict[str, str] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region
    session = boto3.Session(**session_kwargs)
    client = session.client("sqs")

    try:
        response = client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(envelope))
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Failed to send message: {exc}") from exc

    print("AWS send_message response Id:", response.get("MessageId"))


def main() -> None:
    args = parse_args()
    env = args.env.upper()

    props_path = Path(args.properties_file)
    if not props_path.exists():
        raise SystemExit(f"taqt.properties not found at {props_path}")

    props = load_properties(props_path)
    queue_url = resolve_queue_url(env, props, args.queue_url)
    bucket_name, bucket_arn = derive_bucket_info(env, args.bucket_name, args.bucket_arn)
    timestamp = choose_timestamp(args)

    envelope = build_payload(bucket_name, bucket_arn, args.apacif_key, timestamp)
    validate_payload(envelope)

    print("\nPrepared TAQT SQS message:")
    print(json.dumps(envelope, indent=2))
    print()
    print("Queue URL:", queue_url)
    print("Bucket:", bucket_name)
    print("Object key:", args.apacif_key)
    print("Timestamp:", timestamp)

    if args.dry_run:
        print("Dry-run enabled; message was not sent.")
        return

    if not confirm_send(args.yes, queue_url):
        print("Aborted by user.")
        return

    send_message(envelope, queue_url, args)
    print("Message sent successfully.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
