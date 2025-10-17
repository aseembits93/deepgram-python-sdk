from __future__ import annotations

from typing import Any, Dict, Mapping
from urllib.parse import parse_qsl, urlparse

from ..telemetry.handler import TelemetryHandler
from .instrumented_http import HttpEvents
from .instrumented_socket import SocketEvents

_SAFE_KWARGS = [
    'duration_ms', 'error', 'error_type', 'error_message', 'stack_trace',
    'timeout_occurred', 'function_name'
]

_SAFE_KWARGS_SET = set(_SAFE_KWARGS)

_SENSITIVE_KEYS_SET = {'headers', 'params', 'json', 'data', 'content'}

_REQUEST_ID_KEYS = (
    'x-request-id', 'X-Request-Id', 'x-dg-request-id', 'X-DG-Request-Id', 'request-id', 'Request-Id'
)


class TelemetryHttpEvents(HttpEvents):
    def __init__(self, handler: TelemetryHandler):
        self._handler = handler

    def on_http_request(
        self, 
        *, 
        method: str, 
        url: str, 
        headers: Mapping[str, str] | None, 
        extras: Mapping[str, str] | None = None,
        request_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_http_request(
                method=method, 
                url=url, 
                headers=headers, 
                extras=extras,
                request_details=request_details,
            )
        except Exception:
            pass

    def on_http_response(
        self,
        *,
        method: str,
        url: str,
        status_code: int,
        duration_ms: float,
        headers: Mapping[str, str] | None,
        extras: Mapping[str, str] | None = None,
        response_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_http_response(
                method=method,
                url=url,
                status_code=status_code,
                duration_ms=duration_ms,
                headers=headers,
                extras=extras,
                response_details=response_details,
            )
        except Exception:
            pass

    def on_http_error(
        self, 
        *, 
        method: str, 
        url: str, 
        error: BaseException, 
        duration_ms: float,
        request_details: Mapping[str, Any] | None = None,
        response_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_http_error(
                method=method, 
                url=url, 
                error=error, 
                duration_ms=duration_ms,
                request_details=request_details,
                response_details=response_details,
            )
        except Exception:
            pass


class TelemetrySocketEvents(SocketEvents):
    """Implementation of WebSocket events that forwards to a telemetry handler."""
    
    def __init__(self, handler: TelemetryHandler):
        self._handler = handler
    
    def on_ws_connect(
        self,
        *,
        url: str,
        headers: Mapping[str, str] | None = None,
        extras: Mapping[str, str] | None = None,
        request_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_ws_connect(
                url=url,
                headers=headers,
                extras=extras,
                request_details=request_details,
            )
        except Exception:
            pass
    
    def on_ws_error(
        self,
        *,
        url: str,
        error: BaseException,
        duration_ms: float,
        request_details: Mapping[str, Any] | None = None,
        response_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_ws_error(
                url=url,
                error=error,
                extras=None,
                request_details=request_details,
                response_details=response_details,
            )
        except Exception:
            pass
    
    def on_ws_close(
        self,
        *,
        url: str,
        duration_ms: float,
        request_details: Mapping[str, Any] | None = None,
        response_details: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            self._handler.on_ws_close(
                url=url,
            )
        except Exception:
            pass


def filter_sensitive_headers(headers: Mapping[str, str] | None) -> Dict[str, str] | None:
    """Filter out sensitive headers from telemetry, keeping all safe headers."""
    if not headers:
        return None
    
    # Headers to exclude from telemetry for security
    sensitive_prefixes = ('authorization', 'sec-', 'cookie', 'x-api-key', 'x-auth')
    sensitive_headers = {'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token', 'bearer'}
    
    filtered_headers = {}
    for key, value in headers.items():
        key_lower = key.lower()
        
        # Skip sensitive headers
        if key_lower in sensitive_headers:
            continue
        if any(key_lower.startswith(prefix) for prefix in sensitive_prefixes):
            continue
            
        filtered_headers[key] = str(value)
    
    return filtered_headers if filtered_headers else None


def extract_deepgram_headers(headers: Mapping[str, str] | None) -> Dict[str, str] | None:
    """Extract x-dg-* headers from response headers."""
    if not headers:
        return None
    
    dg_headers = {}
    for key, value in headers.items():
        if key.lower().startswith('x-dg-'):
            dg_headers[key.lower()] = str(value)
    
    return dg_headers if dg_headers else None


def capture_request_details(
    method: str | None = None,
    url: str | None = None, 
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    **kwargs
) -> Dict[str, Any]:
    """Capture comprehensive request details for telemetry (keys only for privacy)."""
    details: Dict[str, Any] = {}
    
    if method:
        details['method'] = method
    
    # For URL, capture the structure but not query parameters with values
    if url:
        details['url_structure'] = _extract_url_structure(url)
    
    # For headers, capture only the keys (not values) for privacy
    if headers:
        details['header_keys'] = sorted(list(headers.keys()))
        details['header_count'] = len(headers)
    
    # For query parameters, capture only the keys (not values) for privacy  
    if params:
        details['param_keys'] = sorted(list(params.keys()))
        details['param_count'] = len(params)
    
    # For body content, capture type information but not actual content
    if 'json' in kwargs and kwargs['json'] is not None:
        details['has_json_body'] = True
        details['json_body_type'] = type(kwargs['json']).__name__
    
    if 'data' in kwargs and kwargs['data'] is not None:
        details['has_data_body'] = True
        details['data_body_type'] = type(kwargs['data']).__name__
        
    if 'content' in kwargs and kwargs['content'] is not None:
        details['has_content_body'] = True
        details['content_body_type'] = type(kwargs['content']).__name__
        
    if 'files' in kwargs and kwargs['files'] is not None:
        details['has_files'] = True
        details['files_type'] = type(kwargs['files']).__name__
    
    # Capture any additional request context (excluding sensitive data)
    safe_kwargs = ['timeout', 'follow_redirects', 'max_redirects']
    for key in safe_kwargs:
        if key in kwargs and kwargs[key] is not None:
            details[key] = kwargs[key]
    
    return details


def _extract_url_structure(url: str) -> Dict[str, Any]:
    """Extract URL structure without exposing sensitive query parameter values."""
    try:
        parsed = urlparse(url)

        structure: Dict[str, Any] = {
            'scheme': parsed.scheme,
            'hostname': parsed.hostname,
            'port': parsed.port,
            'path': parsed.path,
        }

        # For query string, only capture the parameter keys, not values
        if parsed.query:
            # Fastest way to collect keys: use parse_qsl to avoid intermediate dict
            keys_seen = set()
            keys: list[str] = []
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                if key not in keys_seen:
                    keys.append(key)
                    keys_seen.add(key)
            keys.sort()
            structure['query_param_keys'] = keys
            structure['query_param_count'] = len(keys_seen)

        return structure
    except Exception:
        # If URL parsing fails, just return a safe representation
        return {'url_parse_error': True, 'url_length': len(url)}


def capture_response_details(response: Any = None, **kwargs) -> Dict[str, Any]:
    """Capture comprehensive response details for telemetry (keys only for privacy)."""
    details = {}

    if response is not None:
        try:
            # Attribute fetches grouped and ordered for minimal hasattr calls
            status_code = getattr(response, 'status_code', None)
            if status_code is not None:
                details['status_code'] = status_code

            headers = getattr(response, 'headers', None)
            if headers is not None:
                keys = list(headers.keys())
                keys.sort()
                details['response_header_keys'] = keys
                details['response_header_count'] = len(keys)

                # Fast: single scan through known keys for known permutations
                for reqid_key in _REQUEST_ID_KEYS:
                    request_id = headers.get(reqid_key)
                    if request_id:
                        details['request_id'] = request_id
                        break

            reason_phrase = getattr(response, 'reason_phrase', None)
            if reason_phrase is not None:
                details['reason_phrase'] = reason_phrase

            url = getattr(response, 'url', None)
            if url is not None:
                details['response_url_structure'] = _extract_url_structure(str(url))
        except Exception:
            pass

    # Safe kwargs (non-sensitive), pre-resolved lookup keys for efficiency
    for key in _SAFE_KWARGS:
        val = kwargs.get(key)
        if val is not None:
            details[key] = val

    # Remaining context (exclude sensitive keys, None values, and safe keys)
    for key, value in kwargs.items():
        # Sets used for fast O(1) lookups
        if (
            key not in _SAFE_KWARGS_SET
            and key not in _SENSITIVE_KEYS_SET
            and value is not None
        ):
            details[key] = value

    return details



