"""Synchronous authenticated client for documented Ideco NGFW write APIs.

This client is intentionally separate from ``app.ngfw.client.NgfwClient``.
The application client is read-only by design; this module belongs to an
explicit, manually invoked administration command.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlsplit

import httpx

from .errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    InputError,
    NetworkError,
)

_SESSION_COOKIE_PREFIXES = ("insecure-ideco-session", "__Secure-ideco-")


def parse_target(raw: str) -> str:
    """Validate a required ``host:port`` and return its HTTPS base URL."""

    value = raw.strip()
    if not value:
        raise InputError("Не указан адрес NGFW в формате domain-or-ip:port")
    if "://" in value:
        raise InputError("Адрес NGFW нужно задавать без схемы, например 192.168.100.11:8443")

    try:
        parsed = urlsplit(f"//{value}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InputError(f"Некорректный адрес NGFW: {exc}") from exc

    if (
        not host
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise InputError("Адрес NGFW должен иметь вид domain-or-ip:port без схемы, пути и логина")
    if not 1 <= port <= 65535:
        raise InputError("Порт NGFW должен находиться в диапазоне 1..65535")

    rendered_host = f"[{host}]" if ":" in host else host
    return f"https://{rendered_host}:{port}"


def _response_detail(response: httpx.Response) -> str:
    """Extract a bounded diagnostic without ever including request data."""

    try:
        payload = response.json()
    except json.JSONDecodeError, ValueError:
        text = response.text.strip()
        return text[:500] if text else "ответ без описания"

    if isinstance(payload, dict):
        for key in ("message", "detail", "error", "msg", "description"):
            value = payload.get(key)
            if value:
                return str(value)[:500]
    return json.dumps(payload, ensure_ascii=False)[:500]


def _secret_values(body: dict[str, Any] | None) -> set[str]:
    if not body:
        return set()
    markers = ("password", "psw", "cookie", "token", "secret")
    return {
        value
        for key, value in body.items()
        if isinstance(value, str) and value and any(marker in key.lower() for marker in markers)
    }


def _redact(text: str, values: set[str]) -> str:
    result = text
    for value in values:
        result = result.replace(value, "[REDACTED]")
    return result


def _looks_like_permission_error(detail: str) -> bool:
    lowered = detail.lower()
    return any(
        marker in lowered
        for marker in (
            "read only",
            "read-only",
            "read_only",
            "только чт",
            "permission denied",
            "access denied",
            "доступ запрещ",
            "forbidden",
        )
    )


class NgfwApiClient:
    """Cookie-session client with readable transport/auth/permission errors."""

    def __init__(
        self,
        target: str,
        login: str,
        password: str,
        *,
        verify: bool | str | Path = True,
        timeout: float = 20.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = parse_target(target)
        self.login_name = login.strip()
        self._password = password
        if not self.login_name:
            raise InputError("Логин администратора не может быть пустым")
        if not password:
            raise InputError("Пароль администратора не может быть пустым")
        if timeout <= 0:
            raise InputError("Таймаут должен быть больше нуля")

        verify_value: bool | str
        if isinstance(verify, Path):
            verify_value = str(verify)
        else:
            verify_value = verify
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify_value,
            timeout=timeout,
            follow_redirects=False,
            headers={"Accept": "application/json"},
            transport=transport,
        )
        self._authenticated = False

    def __enter__(self) -> Self:
        try:
            self.authenticate()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.logout()
        finally:
            self.close()

    def close(self) -> None:
        self._password = ""
        self._client.close()

    def authenticate(self) -> None:
        response = self._send(
            "POST",
            "/web/auth/login",
            json_body={
                "login": self.login_name,
                "password": self._password,
                "rest_path": "/",
            },
            authenticating=True,
        )
        cookie_names = {cookie.name for cookie in self._client.cookies.jar}
        if not any(name.startswith(prefix) for name in cookie_names for prefix in _SESSION_COOKIE_PREFIXES):
            raise ApiError(
                "NGFW подтвердил вход, но не вернул документированную session-cookie",
                hint="Проверьте совместимость версии NGFW и необходимость второго фактора.",
            )
        self._authenticated = True
        # Avoid retaining the administrator password after successful login.
        self._password = ""
        del response

    def logout(self) -> None:
        if not self._authenticated:
            return
        try:
            self._client.delete("/web/auth/login")
        except httpx.HTTPError:
            # The command result is more important than best-effort session cleanup.
            pass
        finally:
            self._authenticated = False

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        response = self._send("GET", path, params=params)
        return self._json(response, path)

    def post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        response = self._send("POST", path, json_body=body, params=params)
        return self._json_or_empty(response, path)

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        response = self._send("PATCH", path, json_body=body)
        return self._json_or_empty(response, path)

    def put(self, path: str, body: dict[str, Any]) -> Any:
        response = self._send("PUT", path, json_body=body)
        return self._json_or_empty(response, path)

    def delete(self, path: str) -> None:
        self._send("DELETE", path)

    def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        authenticating: bool = False,
    ) -> httpx.Response:
        try:
            response = self._client.request(
                method,
                path,
                json=json_body,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"Истёк таймаут обращения к NGFW {self.base_url}",
                hint="Проверьте адрес, порт, маршрутизацию и доступность 8443/tcp.",
            ) from exc
        except httpx.ConnectError as exc:
            reason = type(exc.__cause__).__name__ if exc.__cause__ else type(exc).__name__
            raise NetworkError(
                f"Не удалось установить HTTPS-соединение с NGFW ({reason})",
                hint=(
                    "Проверьте domain:port и сетевую доступность. Если включена "
                    "строгая проверка TLS, проверьте имя сертификата и CA."
                ),
            ) from exc
        except httpx.TransportError as exc:
            raise NetworkError(
                f"Ошибка HTTPS при обращении к NGFW: {type(exc).__name__}",
                hint="Проверьте сертификат, TLS-настройки и сетевую доступность.",
            ) from exc

        status = response.status_code
        cookie_values = {cookie.value for cookie in self._client.cookies.jar}
        detail = _redact(
            _response_detail(response),
            _secret_values(json_body) | cookie_values,
        )
        if authenticating and status in (401, 403):
            raise AuthenticationError(
                "NGFW отклонил логин или пароль администратора",
                hint="Проверьте каталог в логине (@domain/@radius) и второй фактор.",
            )
        if status == 401:
            raise AuthenticationError(
                "Сессия администратора NGFW истекла или была отозвана",
                hint="Повторите запуск и при необходимости проверьте TTL сессии NGFW.",
            )
        if status == 403:
            raise AuthorizationError(
                f"NGFW запретил операцию {method} {path}: {detail}",
                hint=(
                    "У администратора, вероятно, режим «только чтение». "
                    "Запустите команду под отдельным администратором с правами "
                    "изменения пользователей и правил."
                ),
            )
        if method != "GET" and 400 <= status < 500 and _looks_like_permission_error(detail):
            raise AuthorizationError(
                f"NGFW отклонил изменение {method} {path}: {detail}",
                hint=(
                    "Ответ похож на ограничение режима «только чтение». "
                    "Используйте отдельного администратора с правами записи."
                ),
            )
        if status in (409, 422, 542):
            raise ApiError(f"NGFW не принял {method} {path}: {detail}")
        if status == 404:
            raise ApiError(
                f"NGFW не поддерживает документированный endpoint {method} {path}",
                hint="Проверьте версию NGFW; утилита рассчитана на Novum v22 API.",
            )
        if status >= 500:
            raise ApiError(f"NGFW вернул HTTP {status} для {method} {path}: {detail}")
        if not 200 <= status < 300:
            raise ApiError(f"Неожиданный HTTP {status} для {method} {path}: {detail}")
        return response

    @staticmethod
    def _json(response: httpx.Response, path: str) -> Any:
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ApiError(f"NGFW вернул не-JSON ответ для {path}") from exc

    @classmethod
    def _json_or_empty(cls, response: httpx.Response, path: str) -> Any:
        if not response.content:
            return {}
        return cls._json(response, path)
