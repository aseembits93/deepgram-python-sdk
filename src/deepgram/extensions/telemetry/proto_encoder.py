from __future__ import annotations
# isort: skip_file

import struct
import time
import typing
from typing import Dict, List


# --- Protobuf wire helpers (proto3) ---

def _varint(value: int) -> bytes:
    if value < 0:
        # For this usage we only encode non-negative values
        value &= (1 << 64) - 1
    # Fast path for common small values
    if value <= 0x7F:
        return bytes([value])
    out = bytearray()
    append = out.append  # localize for speed
    while value > 0x7F:
        append((value & 0x7F) | 0x80)
        value >>= 7
    append(value)
    return bytes(out)


def _key(field_number: int, wire_type: int) -> bytes:
    return _varint((field_number << 3) | wire_type)


def _len_delimited(field_number: int, payload: bytes) -> bytes:
    k = _key(field_number, 2)
    l = _varint(len(payload))
    # Avoid unnecessary intermediate allocations
    return b"".join((k, l, payload))


def _string(field_number: int, value: str) -> bytes:
    data = value.encode("utf-8")
    k = _key(field_number, 2)
    l = _varint(len(data))
    # Avoid unnecessary intermediate allocations
    return b"".join((k, l, data))


def _bool(field_number: int, value: bool) -> bytes:
    # _varint(1|0) always returns b'\x01' or b'\x00', no need to optimize further
    return _key(field_number, 0) + (b'\x01' if value else b'\x00')


def _int64(field_number: int, value: int) -> bytes:
    return _key(field_number, 0) + _varint(value)


def _double(field_number: int, value: float) -> bytes:
    return _key(field_number, 1) + struct.pack("<d", float(value))


# google.protobuf.Timestamp { seconds: int64(1), nanos: int32(2) }
def _timestamp_message(ts_seconds: float) -> bytes:
    sec = int(ts_seconds)
    nanos = int(round((ts_seconds - sec) * 1_000_000_000))
    if nanos >= 1_000_000_000:
        sec += 1
        nanos -= 1_000_000_000
    parts = []
    parts.append(_int64(1, sec))
    if nanos:
        # nanos fits in 32 bits, fast path varint construction
        parts.append(_key(2, 0))
        parts.append(_varint(nanos))
    return b''.join(parts)


# Map encoders: map<string,string> and map<string,double>
def _map_str_str(field_number: int, items: typing.Mapping[str, str] | None) -> bytes:
    if not items:
        return b""
    # Preallocate list for b''.join for better perf, especially for small maps
    out = []
    # Avoid repeated attribute lookups for tight loop
    out_append = out.append
    _string1 = _string
    _len_delimited1 = _len_delimited
    for k, v in items.items():
        entry = _string1(1, k) + _string1(2, v)
        out_append(_len_delimited1(field_number, entry))
    return b"".join(out)


def _map_str_double(field_number: int, items: typing.Mapping[str, float] | None) -> bytes:
    if not items:
        return b""
    out = bytearray()
    for k, v in items.items():
        entry = _string(1, k) + _double(2, float(v))
        out += _len_delimited(field_number, entry)
    return bytes(out)


# --- Schema-specific encoders (deepgram.dxtelemetry.v1) ---

def _encode_telemetry_context(ctx: typing.Mapping[str, typing.Any]) -> bytes:
    # Map SDK context keys to proto fields
    package_name = ctx.get("sdk_name") or ctx.get("package_name") or "python-sdk"
    package_version = ctx.get("sdk_version") or ctx.get("package_version") or ""
    language = ctx.get("language") or "python"
    runtime_version = ctx.get("runtime_version") or ""
    os_name = ctx.get("os") or ""
    arch = ctx.get("arch") or ""
    app_name = ctx.get("app_name") or ""
    app_version = ctx.get("app_version") or ""
    environment = ctx.get("environment") or ""
    session_id = ctx.get("session_id") or ""
    installation_id = ctx.get("installation_id") or ""
    project_id = ctx.get("project_id") or ""

    msg = bytearray()
    if package_name:
        msg += _string(1, package_name)
    if package_version:
        msg += _string(2, package_version)
    if language:
        msg += _string(3, language)
    if runtime_version:
        msg += _string(4, runtime_version)
    if os_name:
        msg += _string(5, os_name)
    if arch:
        msg += _string(6, arch)
    if app_name:
        msg += _string(7, app_name)
    if app_version:
        msg += _string(8, app_version)
    if environment:
        msg += _string(9, environment)
    if session_id:
        msg += _string(10, session_id)
    if installation_id:
        msg += _string(11, installation_id)
    if project_id:
        msg += _string(12, project_id)
    
    # Include extras as additional context attributes (field 13)
    extras = ctx.get("extras", {})
    if extras:
        # Convert extras to string-string map for protobuf
        extras_map = {}
        for key, value in extras.items():
            if value is not None:
                extras_map[str(key)] = str(value)
        msg += _map_str_str(13, extras_map)
    
    return bytes(msg)


def _encode_telemetry_event(name: str, ts: float, attributes: Dict[str, str] | None, metrics: Dict[str, float] | None) -> bytes:
    msg = bytearray()
    msg += _string(1, name)
    msg += _len_delimited(2, _timestamp_message(ts))
    msg += _map_str_str(3, attributes)
    msg += _map_str_double(4, metrics)
    return bytes(msg)


# ErrorSeverity enum values: ... INFO=1, WARNING=2, ERROR=3, CRITICAL=4
def _encode_error_event(
    *,
    err_type: str,
    message: str,
    severity: int,
    handled: bool,
    ts: float,
    attributes: Dict[str, str] | None,
    stack_trace: str | None = None,
    file: str | None = None,
    line: int | None = None,
    column: int | None = None,
) -> bytes:
    msg = []
    append = msg.append

    if err_type:
        append(_string(1, err_type))
    if message:
        append(_string(2, message))
    if stack_trace:
        append(_string(3, stack_trace))
    if file:
        append(_string(4, file))
    if line is not None:
        append(_key(5, 0))
        append(_varint(line))
    if column is not None:
        append(_key(6, 0))
        append(_varint(column))
    append(_key(7, 0))
    append(_varint(severity))
    append(_bool(8, handled))
    append(_len_delimited(9, _timestamp_message(ts)))
    append(_map_str_str(10, attributes))
    return b"".join(msg)


def _encode_record(record: bytes, kind_field_number: int) -> bytes:
    # kind_field_number: 1 for telemetry, 2 for error
    return _len_delimited(2, _len_delimited(kind_field_number, record))


def _normalize_events(events: List[dict]) -> List[bytes]:
    out: List[bytes] = []
    for e in events:
        etype = e.get("type")
        ts = float(e.get("ts", time.time()))
        if etype == "http_request":
            attrs = {
                "method": str(e.get("method", "")),
                # Note: URL is never logged for privacy
            }
            # Add request_id if present in headers for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            rec = _encode_telemetry_event("http.request", ts, attrs, None)
            out.append(_encode_record(rec, 1))
        elif etype == "http_response":
            attrs = {
                "method": str(e.get("method", "")),
                "status_code": str(e.get("status_code", "")),
                # Note: URL is never logged for privacy
            }
            # Add request_id if present in headers for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            metrics = {"duration_ms": float(e.get("duration_ms", 0.0))}
            rec = _encode_telemetry_event("http.response", ts, attrs, metrics)
            out.append(_encode_record(rec, 1))
        elif etype == "http_error":
            attrs = {
                "method": str(e.get("method", "")),
                # Note: URL is never logged for privacy
            }
            # Include status_code if present
            sc = e.get("status_code")
            if sc is not None:
                attrs["status_code"] = str(sc)
            # Add request_id if present in headers for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            rec = _encode_error_event(
                err_type=str(e.get("error", "Error")),
                message=str(e.get("message", "")),
                severity=3,
                handled=bool(e.get("handled", True)),
                ts=ts,
                attributes=attrs,
                stack_trace=str(e.get("stack_trace", "")) or None,
            )
            out.append(_encode_record(rec, 2))
        elif etype == "ws_connect":
            attrs = {
                # Note: URL is never logged for privacy
                "connection_type": "websocket",
            }
            # Add request_id if present for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            rec = _encode_telemetry_event("ws.connect", ts, attrs, None)
            out.append(_encode_record(rec, 1))
        elif etype == "ws_error":
            attrs = {
                # Note: URL is never logged for privacy
                "connection_type": "websocket",
            }
            
            # Add detailed error information to attributes
            if e.get("error_type"):
                attrs["error_type"] = str(e["error_type"])
            if e.get("function_name"):
                attrs["function_name"] = str(e["function_name"])
            if e.get("sdk_function"):
                attrs["sdk_function"] = str(e["sdk_function"])
            if e.get("timeout_occurred"):
                attrs["timeout_occurred"] = str(e["timeout_occurred"])
            if e.get("duration_ms"):
                attrs["duration_ms"] = str(e["duration_ms"])
            
            # Add WebSocket handshake failure details
            if e.get("handshake_status_code"):
                attrs["handshake_status_code"] = str(e["handshake_status_code"])
            if e.get("handshake_reason_phrase"):
                attrs["handshake_reason_phrase"] = str(e["handshake_reason_phrase"])
            if e.get("handshake_error_type"):
                attrs["handshake_error_type"] = str(e["handshake_error_type"])
            if e.get("handshake_response_headers"):
                # Include important handshake response headers
                handshake_headers = e["handshake_response_headers"]
                for header_name, header_value in handshake_headers.items():
                    # Prefix with 'handshake_' to distinguish from request headers
                    safe_header_name = header_name.lower().replace('-', '_')
                    attrs[f"handshake_{safe_header_name}"] = str(header_value)
            
            # Add connection parameters if available
            if e.get("connection_params"):
                for key, value in e["connection_params"].items():
                    if value is not None:
                        attrs[f"connection_{key}"] = str(value)
            
            # Add request_id if present for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            
            # Include ALL extras in the attributes for comprehensive telemetry
            extras = e.get("extras", {})
            if extras:
                for key, value in extras.items():
                    if value is not None and key not in attrs:
                        attrs[str(key)] = str(value)
            
            rec = _encode_error_event(
                err_type=str(e.get("error_type", e.get("error", "Error"))),
                message=str(e.get("error_message", e.get("message", ""))),
                severity=3,
                handled=bool(e.get("handled", True)),
                ts=ts,
                attributes=attrs,
                stack_trace=str(e.get("stack_trace", "")) or None,
            )
            out.append(_encode_record(rec, 2))
        elif etype == "uncaught_error":
            rec = _encode_error_event(
                err_type=str(e.get("error", "Error")),
                message=str(e.get("message", "")),
                severity=4 if not bool(e.get("handled", False)) else 3,
                handled=bool(e.get("handled", False)),
                ts=ts,
                attributes=None,
                stack_trace=str(e.get("stack_trace", "")) or None,
            )
            out.append(_encode_record(rec, 2))
        elif etype == "ws_close":
            attrs = {
                # Note: URL is never logged for privacy
                "connection_type": "websocket",
            }
            # Add request_id if present for server-side correlation
            request_id = e.get("request_id")
            if request_id:
                attrs["request_id"] = str(request_id)
            rec = _encode_telemetry_event("ws.close", ts, attrs, None)
            out.append(_encode_record(rec, 1))
        elif etype == "telemetry_event":
            # Generic telemetry event with custom name
            name = e.get("name", "unknown")
            attrs = dict(e.get("attributes", {}))
            metrics = e.get("metrics", {})
            # Convert metrics to float values
            if metrics:
                metrics = {k: float(v) for k, v in metrics.items()}
            rec = _encode_telemetry_event(name, ts, attrs, metrics)
            out.append(_encode_record(rec, 1))
        elif etype == "error_event":
            # Generic error event
            attrs = dict(e.get("attributes", {}))
            rec = _encode_error_event(
                err_type=str(e.get("error_type", "Error")),
                message=str(e.get("message", "")),
                severity=int(e.get("severity", 3)),
                handled=bool(e.get("handled", True)),
                ts=ts,
                attributes=attrs,
                stack_trace=str(e.get("stack_trace", "")) or None,
                file=str(e.get("file", "")) or None,
                line=int(e.get("line", 0)) if e.get("line") else None,
                column=int(e.get("column", 0)) if e.get("column") else None,
            )
            out.append(_encode_record(rec, 2))
        else:
            # Unknown event: drop silently
            continue
    return out


def encode_telemetry_batch(events: List[dict], context: typing.Mapping[str, typing.Any]) -> bytes:
    ctx = _encode_telemetry_context(context)
    records = b"".join(_normalize_events(events))
    batch = _len_delimited(1, ctx) + records
    return batch


def encode_telemetry_batch_iter(events: List[dict], context: typing.Mapping[str, typing.Any]) -> typing.Iterator[bytes]:
    # Streaming variant: yield small chunks (context first, then each record)
    yield _len_delimited(1, _encode_telemetry_context(context))
    for rec in _normalize_events(events):
        yield rec


