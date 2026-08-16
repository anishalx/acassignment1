"""Optional: the same subsystem driven over real TCP sockets.

Run from the repository root::

    python -m demo.run_network_demo
    python -m demo.run_network_demo --suite chacha20-poly1305 --records 12

Section 3.3 permits a purely logical exchange between sender and receiver, and
``run_demo.py`` takes that option.  This script exists to make the point that the
choice was genuinely free: the subsystem produces and consumes self-contained
byte strings, so moving it onto a socket requires no change to ``srp`` at all.

Three processes-worth of entities run as three threads joined by two TCP
connections::

    Sender  --TCP-->  Malicious Actor (on-path proxy)  --TCP-->  Receiver

The actor is a real man-in-the-middle here rather than a function call: it holds
both sockets, sees every byte, and rewrites some of them before forwarding.
That is the exact capability the threat model assumes, and it is worth showing
concretely because it makes clear the actor needs no privileged position inside
the application to mount every attack in TR-2 through TR-5.

Note that the 4-byte length prefix used below is *transport framing*, not part of
the protected record.  Reliable delivery and message boundaries are out of scope
(Section 3.2); the record's own authenticated ``payload_len`` is what the
subsystem trusts.
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from srp import (  # noqa: E402
    SUITE_NAMES,
    MaliciousActor,
    Receiver,
    RecordType,
    Sender,
    new_session_id,
    suite_class,
)

TIMEOUT = 20.0


# -- transport framing (not part of the protected record) --------------------

def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_exact(sock: socket.socket, count: int) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer += chunk
    return bytes(buffer)


def recv_frame(sock: socket.socket) -> bytes | None:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    return recv_exact(sock, int.from_bytes(header, "big"))


# -- the three entities ------------------------------------------------------

def receiver_entity(listener: socket.socket, receiver: Receiver, log: list) -> None:
    """Accepts one connection and verifies every record that arrives."""
    conn, _ = listener.accept()
    conn.settimeout(TIMEOUT)
    with conn:
        while True:
            wire = recv_frame(conn)
            if wire is None:
                return
            verdict = receiver.receive(wire)
            log.append(verdict)


def actor_entity(
    listener: socket.socket,
    upstream: tuple[str, int],
    actor: MaliciousActor,
    plan: dict[int, str],
    log: list,
) -> None:
    """On-path proxy: forwards records, rewriting the ones the plan names."""
    conn, _ = listener.accept()
    conn.settimeout(TIMEOUT)
    captured: bytes | None = None
    captured_index: int | None = None

    with conn, socket.create_connection(upstream, timeout=TIMEOUT) as out:
        index = 0
        while True:
            wire = recv_frame(conn)
            if wire is None:
                return
            action = plan.get(index, "forward")

            # ``log`` records what was put on the wire *towards the receiver*, in
            # send order, so it lines up one-for-one with the receiver's
            # verdicts.  A dropped record contributes nothing; a replay
            # contributes two entries.
            if action == "forward":
                send_frame(out, wire)
                log.append((index, "forward"))
                if captured is None:
                    captured, captured_index = wire, index  # keep for a later replay
            elif action == "flip-ciphertext":
                send_frame(out, actor.flip_ciphertext_bit(wire))
                log.append((index, "flip-ciphertext"))
            elif action == "flip-tag":
                send_frame(out, actor.flip_tag_bit(wire))
                log.append((index, "flip-tag"))
            elif action == "tamper-aad":
                send_frame(out, actor.relabel_record_type(wire, RecordType.CLOSE))
                log.append((index, "tamper-aad"))
            elif action == "drop":
                pass  # suppressed entirely: never reaches the receiver
            elif action == "replay":
                send_frame(out, wire)
                log.append((index, "forward"))
                if captured is not None:
                    send_frame(out, actor.replay(captured))
                    log.append((captured_index, "replay"))
            index += 1


def sender_entity(address: tuple[str, int], sender: Sender, count: int) -> list[bytes]:
    """Protects and transmits ``count`` application records."""
    payloads = [f"application record {i:04d}".encode() for i in range(count)]
    with socket.create_connection(address, timeout=TIMEOUT) as sock:
        for payload in payloads:
            send_frame(sock, sender.protect(payload))
    return payloads


# -- driver ------------------------------------------------------------------

def run(suite_name: str, records: int) -> bool:
    cls = suite_class(suite_name)
    key = cls.generate_key()          # pre-shared, per Section 3.3
    session_id = new_session_id()

    sender = Sender(cls(key), session_id)
    receiver = Receiver(cls(key), expected_session_id=session_id)
    actor = MaliciousActor(random.Random(0xC56530))

    plan = {
        2: "flip-ciphertext",
        4: "flip-tag",
        6: "tamper-aad",
        8: "drop",
        9: "replay",
    }

    receiver_listener = socket.socket()
    receiver_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receiver_listener.bind(("127.0.0.1", 0))
    receiver_listener.listen(1)
    receiver_listener.settimeout(TIMEOUT)
    receiver_addr = receiver_listener.getsockname()

    actor_listener = socket.socket()
    actor_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    actor_listener.bind(("127.0.0.1", 0))
    actor_listener.listen(1)
    actor_listener.settimeout(TIMEOUT)
    actor_addr = actor_listener.getsockname()

    verdicts: list = []
    actions: list = []

    threads = [
        threading.Thread(target=receiver_entity, args=(receiver_listener, receiver, verdicts)),
        threading.Thread(target=actor_entity,
                         args=(actor_listener, receiver_addr, actor, plan, actions)),
    ]
    for thread in threads:
        thread.daemon = True
        thread.start()

    print("=" * 78)
    print(f" Network demonstration -- {suite_name}")
    print("=" * 78)
    print(f"  Sender          -> 127.0.0.1:{actor_addr[1]}  (the actor's listening port)")
    print(f"  Malicious Actor -> 127.0.0.1:{receiver_addr[1]}  (the receiver's port)")
    print(f"  records to send : {records}")
    print("-" * 78)

    payloads = sender_entity(actor_addr, sender, records)

    for thread in threads:
        thread.join(timeout=TIMEOUT)
    receiver_listener.close()
    actor_listener.close()

    print(f"  {'record':>6}  {'actor action':<17} {'receiver verdict':<45}")
    print("-" * 78)
    for (record_index, action), verdict in zip(actions, verdicts):
        marker = " " if action == "forward" else "*"
        print(f"  {record_index:>6}{marker} {action:<17} {verdict.describe()[:45]:<45}")
    dropped = sorted(i for i, a in plan.items() if a == "drop" and i < records)
    for index in dropped:
        print(f"  {index:>6}* {'drop':<17} {'(never reached the receiver)':<45}")
    print("-" * 78)
    print("  * = the malicious actor interfered with this record")
    print("-" * 78)

    stats = receiver.stats
    print(f"  accepted         {stats.accepted}")
    print(f"  rejected         {stats.rejected_total}  {stats.rejected}")

    expected_accepted = records - len({2, 4, 6, 8} & set(range(records)))
    expected_rejections = {
        "AUTH_FAILED": len({2, 4, 6} & set(range(records))),
        "REPLAY_DETECTED": 1 if records > 9 else 0,
    }
    expected_rejections = {k: v for k, v in expected_rejections.items() if v}

    ok = (
        stats.accepted == expected_accepted
        and stats.rejected == expected_rejections
        and all(
            v.plaintext is not None or v.rejected for v in verdicts
        )
    )
    print(f"  expected accepted {expected_accepted}, rejections {expected_rejections}")
    print(f"  RESULT           {'PASS' if ok else 'FAIL'}")
    print("=" * 78)
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", choices=SUITE_NAMES, action="append",
                        help="AEAD configuration (repeatable; default: both)")
    parser.add_argument("--records", type=int, default=12,
                        help="number of application records to send (default: 12)")
    args = parser.parse_args(argv)

    suites = args.suite or list(SUITE_NAMES)
    ok = True
    for suite_name in suites:
        ok &= run(suite_name, args.records)
        print()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
