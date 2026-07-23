"""Idempotent orchestration of isolated STUCK test data on an NGFW."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .client import NgfwApiClient
from .errors import ApiError, ConflictError, InputError, NgfwToolError

ROOT_VCE_GROUP_ID = "f3ffde22-a562-4f43-ac04-c40fcec6a88c"
DEFAULT_PARENT_GROUP_ID = "group.id.1"
FW_PORT_TEST_IP = "198.51.100.25"
FW_PORT_TEST_PORT = 9443
# Hardware filtering (optional NGFW section, v22+): TEST-NET addresses for the
# three IP rule lists. Exact addresses without masks, per the documented API.
HW_SRC_TEST_IP = "192.0.2.77"
HW_DST_TEST_IP = "203.0.113.77"
HW_PAIR_SRC_IP = "192.0.2.78"
HW_PAIR_DST_IP = "203.0.113.78"


@dataclass(frozen=True)
class SeedOptions:
    prefix: str = "STUCK TEST"
    parent_group_id: str = DEFAULT_PARENT_GROUP_ID
    test_user_login: str = "stuck-test-user"
    test_user_password: str = ""
    include_dns: bool = False
    enable_modules: bool = False


@dataclass
class SeedSummary:
    created: list[str] = field(default_factory=list)
    reused: list[str] = field(default_factory=list)
    planned: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Rollback:
    description: str
    method: str
    path: str
    body: dict[str, Any] | None = None


class NgfwTestDataSeeder:
    """Create a deterministic, prefix-owned verification data set.

    Existing resources are reused only when their identifying fields match the
    requested definition. A same-name/different-value resource is treated as a
    conflict rather than being overwritten.
    """

    def __init__(
        self,
        client: NgfwApiClient,
        options: SeedOptions,
        *,
        emit: Callable[[str], None] = print,
    ) -> None:
        self.client = client
        self.options = options
        self.emit = emit
        self.summary = SeedSummary()
        self._rollbacks: list[_Rollback] = []
        self._validate_options()

    def seed(self, *, apply: bool) -> SeedSummary:
        mode = "ПРИМЕНЕНИЕ" if apply else "ПЛАН (без изменений)"
        self.emit(f"\n== {mode} ==")
        self.emit(f"Префикс ресурсов: {self.options.prefix!r}")

        try:
            group_id = self._ensure_group(apply)
            user_id = self._ensure_user(group_id, apply)

            fw_ip_id = self._ensure_alias(
                endpoint="ip_addresses",
                kind="IP-объект",
                title=self._name("FW block IP"),
                value="203.0.113.10",
                apply=apply,
            )
            fw_domain_id = self._ensure_alias(
                endpoint="domains",
                kind="domain-объект",
                title=self._name("FW block domain"),
                value="example.org",
                apply=apply,
            )
            fw_port_ip_id = self._ensure_alias(
                endpoint="ip_addresses",
                kind="IP-объект",
                title=self._name("FW port target"),
                value=FW_PORT_TEST_IP,
                apply=apply,
            )
            fw_port_id = self._ensure_alias(
                endpoint="ports",
                kind="порт-объект",
                title=self._name("FW blocked port"),
                value=FW_PORT_TEST_PORT,
                apply=apply,
            )
            ips_bypass_id = self._ensure_alias(
                endpoint="ip_addresses",
                kind="IP-объект",
                title=self._name("IPS bypass"),
                value="192.0.2.30",
                apply=apply,
            )

            block_category_id = self._ensure_category(self._name("CF block category"), ["cf-block.example"], apply)
            redirect_category_id = self._ensure_category(
                self._name("CF redirect category"), ["cf-redirect.example"], apply
            )

            self._ensure_content_filter_rule(
                name=self._name("CF deny"),
                user_id=user_id,
                category_id=block_category_id,
                access="deny",
                redirect_url=None,
                apply=apply,
            )
            self._ensure_content_filter_rule(
                name=self._name("CF redirect"),
                user_id=user_id,
                category_id=redirect_category_id,
                access="redirect",
                redirect_url="https://example.com/",
                apply=apply,
            )

            self._ensure_firewall_rule(
                comment=self._comment("FW reject 203.0.113.10"),
                user_id=user_id,
                destination_id=fw_ip_id,
                action="reject",
                apply=apply,
            )
            self._ensure_firewall_rule(
                comment=self._comment("FW drop example.org"),
                user_id=user_id,
                destination_id=fw_domain_id,
                action="drop",
                apply=apply,
            )
            # Create the broad allow first and the narrow deny second. Both are
            # inserted at the top, so the final order is narrow -> broad.
            self._ensure_firewall_rule(
                comment=self._comment(f"FW allow {FW_PORT_TEST_IP}:any"),
                user_id=user_id,
                destination_id=fw_port_ip_id,
                action="accept",
                apply=apply,
            )
            self._ensure_firewall_rule(
                comment=self._comment(f"FW drop {FW_PORT_TEST_IP}:{FW_PORT_TEST_PORT}"),
                user_id=user_id,
                destination_id=fw_port_ip_id,
                destination_port_id=fw_port_id,
                action="drop",
                apply=apply,
            )
            self._verify_managed_rule_order(apply)
            self._ensure_ips_bypass(ips_bypass_id, apply)
            self._ensure_hw_rules(apply)

            if self.options.include_dns:
                self._ensure_dns_zone(apply)
            else:
                self._warn(
                    "DNS test-zone пропущена; добавьте --include-dns, чтобы создать stuck-dns.test → 192.0.2.53."
                )

            self._check_modules(apply)
            self._warn(
                "Ограничение скорости не добавлено: в предоставленных "
                "docs/source и toc.yaml отсутствует документированный shaper API."
            )
            self._show_test_matrix()
            return self.summary
        except NgfwToolError:
            if apply:
                self._rollback()
            raise
        except Exception as exc:
            if apply:
                self._rollback()
            raise ApiError(f"Непредвиденная ошибка подготовки тестовых данных: {exc}") from exc

    def _validate_options(self) -> None:
        prefix = self.options.prefix.strip()
        if not prefix:
            raise InputError("Префикс тестовых ресурсов не может быть пустым")
        if any(ord(char) < 32 for char in prefix):
            raise InputError("Префикс содержит управляющие символы")
        if len(self._name("CF redirect category")) > 42:
            raise InputError("Префикс слишком длинный: названия объектов NGFW ограничены 42 символами")
        if not self.options.parent_group_id.strip():
            raise InputError("parent_group_id не может быть пустым")
        if not self.options.test_user_login.strip():
            raise InputError("Логин тестового пользователя не может быть пустым")

    def _name(self, suffix: str) -> str:
        return f"{self.options.prefix.strip()} - {suffix}"

    def _comment(self, suffix: str) -> str:
        return f"[{self.options.prefix.strip()}] {suffix}"

    @staticmethod
    def _as_list(value: Any, endpoint: str) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ApiError(f"NGFW вернул неожиданную схему списка для {endpoint}")
        return value

    @staticmethod
    def _created_id(payload: Any, kind: str, endpoint: str) -> str:
        if not isinstance(payload, dict) or payload.get("id") is None:
            raise ApiError(f"NGFW не вернул id созданного ресурса для {endpoint}")
        return str(payload["id"])

    @staticmethod
    def _typed_id(kind: str, value: Any) -> str:
        raw = str(value)
        prefix = f"{kind}.id."
        return raw if raw.startswith(prefix) else f"{prefix}{raw}"

    @classmethod
    def _same_typed_id(cls, kind: str, left: Any, right: Any) -> bool:
        return cls._typed_id(kind, left) == cls._typed_id(kind, right)

    def _record_created(self, label: str, rollback: _Rollback) -> None:
        self.summary.created.append(label)
        self._rollbacks.append(rollback)
        self.emit(f"[CREATED] {label}")

    def _record_reused(self, label: str) -> None:
        self.summary.reused.append(label)
        self.emit(f"[EXISTS]  {label}")

    def _record_planned(self, label: str) -> None:
        self.summary.planned.append(label)
        self.emit(f"[PLAN]    {label}")

    def _warn(self, message: str) -> None:
        self.summary.warnings.append(message)
        self.emit(f"[NOTICE]  {message}")

    def _ensure_group(self, apply: bool) -> str:
        groups = self._as_list(self.client.get("/user_backend/groups"), "groups")
        requested_parent = self.options.parent_group_id
        parent_match = next(
            (item for item in groups if self._same_typed_id("group", item.get("id"), requested_parent)),
            None,
        )
        if parent_match is None:
            raise ConflictError(
                f"Родительская группа {requested_parent!r} не найдена",
                hint="Передайте существующий id через --parent-group-id.",
            )
        parent_api_id = parent_match["id"]

        name = self._name("group")
        matches = [item for item in groups if item.get("name") == name]
        if matches:
            match = matches[0]
            if not self._same_typed_id("group", match.get("parent_id"), parent_api_id):
                raise ConflictError(f"Группа {name!r} уже существует под другим родителем")
            group_id = str(match.get("id"))
            self._record_reused(f"группа {name} ({group_id})")
            return group_id

        label = f"группа {name} под {requested_parent} (API id={parent_api_id})"
        if not apply:
            self._record_planned(label)
            return "planned.group"
        payload = self.client.post("/user_backend/groups", {"name": name, "parent_id": parent_api_id})
        group_id = self._created_id(payload, "group", "/user_backend/groups")
        self._record_created(
            f"группа {name} ({group_id})",
            _Rollback("группа", "DELETE", f"/user_backend/groups/{quote(group_id)}"),
        )
        return group_id

    def _ensure_user(self, group_id: str, apply: bool) -> str:
        users = self._as_list(self.client.get("/user_backend/users"), "users")
        login = self.options.test_user_login.strip()
        name = self._name("user")
        matches = [item for item in users if item.get("login") == login]
        if matches:
            match = matches[0]
            if not self._same_typed_id("group", match.get("parent_id"), group_id) or match.get("name") != name:
                raise ConflictError(
                    f"Логин тестового пользователя {login!r} уже занят другим объектом",
                    hint="Используйте --test-user-login с другим значением.",
                )
            user_id = self._typed_id("user", match.get("id"))
            self._record_reused(f"пользователь {login} ({user_id})")
            return user_id

        label = f"пользователь {login} в {group_id}"
        if not apply:
            self._record_planned(label)
            return "planned.user"
        if not self.options.test_user_password:
            raise InputError("Для применения не задан пароль тестового пользователя")
        payload = self.client.post(
            "/user_backend/users",
            {
                "name": name,
                "login": login,
                "psw": self.options.test_user_password,
                "parent_id": group_id,
                "phone_number": None,
                "comment": self._comment("isolated UI verification user"),
            },
        )
        raw_user_id = self._created_id(payload, "user", "/user_backend/users")
        user_id = self._typed_id("user", raw_user_id)
        self._record_created(
            f"пользователь {login} ({user_id})",
            _Rollback(
                "пользователь",
                "DELETE",
                f"/user_backend/users/{quote(raw_user_id)}",
            ),
        )
        return user_id

    def _ensure_alias(
        self,
        *,
        endpoint: str,
        kind: str,
        title: str,
        value: str | int,
        apply: bool,
    ) -> str:
        path = f"/aliases/{endpoint}"
        aliases = self._as_list(self.client.get(path), path)
        matches = [item for item in aliases if item.get("title") == title]
        if matches:
            match = matches[0]
            if str(match.get("value")) != str(value):
                raise ConflictError(
                    f"Объект {title!r} уже существует со значением {match.get('value')!r}, ожидалось {value!r}",
                    hint="Удалите конфликтующий тестовый объект или смените --prefix.",
                )
            alias_id = str(match.get("id"))
            self._record_reused(f"{kind} {title}={value} ({alias_id})")
            return alias_id

        label = f"{kind} {title}={value}"
        if not apply:
            self._record_planned(label)
            return f"planned.{endpoint}.{value}"
        payload = self.client.post(
            path,
            {
                "title": title,
                "comment": self._comment("isolated documentation address"),
                "value": value,
            },
        )
        alias_id = self._created_id(payload, "alias", path)
        self._record_created(
            f"{kind} {title}={value} ({alias_id})",
            _Rollback(kind, "DELETE", f"{path}/{quote(alias_id)}"),
        )
        # Do not trust only the POST status/returned id: read the collection
        # back and verify what NGFW actually persisted. This also catches API
        # shape changes where a write appears successful but loses the value.
        persisted = self._as_list(self.client.get(path), path)
        saved = next(
            (item for item in persisted if str(item.get("id")) == alias_id),
            None,
        )
        if saved is None:
            raise ConflictError(
                f"NGFW сообщил о создании объекта {title!r}, но объект не найден при проверке",
                hint="Проверьте права администратора и совместимость версии API NGFW.",
            )
        if saved.get("title") != title or str(saved.get("value")) != str(value):
            raise ConflictError(
                f"NGFW сохранил объект {title!r} с неожиданными полями",
                hint=(
                    f"Ожидались title={title!r}, value={value!r}; "
                    f"получены title={saved.get('title')!r}, value={saved.get('value')!r}."
                ),
            )
        self.emit(f"[OBJECT OK] {kind} {title}={value} ({alias_id})")
        return alias_id

    def _ensure_category(self, name: str, urls: list[str], apply: bool) -> str:
        path = "/content-filter/users_categories"
        categories = self._as_list(self.client.get(path), path)
        matches = [item for item in categories if item.get("name") == name]
        if matches:
            match = matches[0]
            if set(match.get("urls") or []) != set(urls):
                raise ConflictError(
                    f"Категория {name!r} существует с другим списком URL",
                    hint="Удалите конфликтующую категорию или смените --prefix.",
                )
            category_id = str(match.get("id"))
            self._record_reused(f"категория {name}: {', '.join(urls)} ({category_id})")
            return category_id

        label = f"категория {name}: {', '.join(urls)}"
        if not apply:
            self._record_planned(label)
            return f"planned.category.{name}"
        payload = self.client.post(
            path,
            {
                "name": name,
                "comment": self._comment("custom category for UI verification"),
                "urls": urls,
            },
        )
        category_id = self._created_id(payload, "category", path)
        self._record_created(
            f"категория {name}: {', '.join(urls)} ({category_id})",
            _Rollback("категория", "DELETE", f"{path}/{quote(category_id)}"),
        )
        return category_id

    def _ensure_content_filter_rule(
        self,
        *,
        name: str,
        user_id: str,
        category_id: str,
        access: str,
        redirect_url: str | None,
        apply: bool,
    ) -> None:
        path = "/content-filter/rules"
        rules = self._as_list(self.client.get(path), path)
        matches = [item for item in rules if item.get("name") == name]
        expected = {
            "aliases": {user_id},
            "categories": {category_id},
            "access": access,
            "redirect_url": redirect_url,
        }
        if matches:
            match = matches[0]
            actual = {
                "aliases": self._content_filter_alias_tokens(match),
                "categories": set(match.get("categories") or []),
                "access": match.get("access"),
                "redirect_url": match.get("redirect_url"),
            }
            if actual != expected:
                raise ConflictError(f"Правило Контент-фильтра {name!r} отличается от ожидаемого")
            self._record_reused(f"правило Контент-фильтра {name} ({match.get('id')})")
            return

        label = f"правило Контент-фильтра {name} ({access})"
        if not apply:
            self._record_planned(label)
            return
        body = {
            "name": name,
            "comment": self._comment(f"content filter {access}"),
            "parent_id": self._rule_parent_id(rules),
            "src_aliases": [{"aliases": [user_id], "negate": False}],
            "categories": [category_id],
            "categories_negate": False,
            "http_methods": [],
            "content_types": [],
            "content_length": 0,
            "content_length_mode": "le",
            "traffic_direction": "both",
            "uri_regex": [],
            "av_profile": "",
            "access": access,
            "redirect_url": redirect_url,
            "enabled": True,
            "timetable": ["any"],
        }
        params = self._insert_first_params(rules)
        payload = self.client.post(path, body, params=params)
        rule_id = self._created_id(payload, "cf_rule", path)
        self._record_created(
            f"правило Контент-фильтра {name} ({rule_id})",
            _Rollback("правило Контент-фильтра", "DELETE", f"{path}/{quote(rule_id)}"),
        )

    def _ensure_firewall_rule(
        self,
        *,
        comment: str,
        user_id: str,
        destination_id: str,
        destination_port_id: str = "any",
        action: str,
        apply: bool,
    ) -> None:
        path = "/firewall/rules/forward"
        rules = self._as_list(self.client.get(path), path)
        matches = [item for item in rules if item.get("comment") == comment]
        if matches:
            match = matches[0]
            sources = self._address_tokens(match.get("sources"))
            destinations = self._address_tokens(match.get("destinations"))
            destination_ports = {str(value) for value in (match.get("destination_ports") or [])}
            if (
                sources != {user_id}
                or destinations != {destination_id}
                or destination_ports != {destination_port_id}
                or match.get("action") != action
            ):
                raise ConflictError(f"Правило FORWARD {comment!r} отличается от ожидаемого")
            self._record_reused(f"правило FORWARD {comment} ({match.get('id')})")
            return

        label = f"правило FORWARD {comment} ({action})"
        if not apply:
            self._record_planned(label)
            return
        body = {
            "parent_id": self._rule_parent_id(rules),
            "enabled": True,
            "logging": False,
            "protocol": "protocol.tcp",
            "sources": [{"addresses": [user_id], "addresses_negate": False}],
            "source_ports": ["any"],
            "incoming_interface": "any",
            "destinations": [{"addresses": [destination_id], "addresses_negate": False}],
            "destination_ports": [destination_port_id],
            "outgoing_interface": "any",
            "hip_profiles": [],
            "hip_profiles_negate": False,
            "dpi_profile": "",
            "dpi_enabled": False,
            "ips_profile": "",
            "ips_enabled": False,
            "timetable": ["any"],
            "comment": comment,
            "action": action,
        }
        payload = self.client.post(path, body, params=self._insert_first_params(rules))
        rule_id = self._created_id(payload, "fw_rule", path)
        self._record_created(
            f"правило FORWARD {comment} ({rule_id})",
            _Rollback("правило FORWARD", "DELETE", f"{path}/{quote(rule_id)}"),
        )

    def _verify_managed_rule_order(self, apply: bool) -> None:
        if not apply:
            return

        expected_cf = [self._name("CF redirect"), self._name("CF deny")]
        expected_fw = [
            self._comment(f"FW drop {FW_PORT_TEST_IP}:{FW_PORT_TEST_PORT}"),
            self._comment(f"FW allow {FW_PORT_TEST_IP}:any"),
            self._comment("FW drop example.org"),
            self._comment("FW reject 203.0.113.10"),
        ]
        cf_rules = self._as_list(self.client.get("/content-filter/rules"), "content-filter/rules")
        fw_rules = self._as_list(self.client.get("/firewall/rules/forward"), "firewall/rules/forward")
        actual_cf = [str(rule.get("name")) for rule in cf_rules[: len(expected_cf)]]
        actual_fw = [str(rule.get("comment")) for rule in fw_rules[: len(expected_fw)]]
        if actual_cf != expected_cf:
            raise ConflictError(
                "Нарушен порядок тестовых правил Контент-фильтра",
                hint=f"Ожидались первые правила: {expected_cf!r}; получены: {actual_cf!r}.",
            )
        if actual_fw != expected_fw:
            raise ConflictError(
                "Нарушен порядок тестовых правил FORWARD",
                hint=f"Ожидались первые правила: {expected_fw!r}; получены: {actual_fw!r}.",
            )
        self.emit("[ORDER OK] Первые подходящие CF/FORWARD-правила имеют ожидаемый приоритет")

    def _ensure_ips_bypass(self, alias_id: str, apply: bool) -> None:
        path = "/ips/bypass"
        entries = self._as_list(self.client.get(path), path)
        comment = self._comment("IPS bypass 192.0.2.30")
        matches = [item for item in entries if item.get("comment") == comment]
        if matches:
            match = matches[0]
            if set(match.get("aliases") or []) != {alias_id}:
                raise ConflictError(f"Исключение IPS {comment!r} отличается от ожидаемого")
            self._record_reused(f"исключение IPS {comment} ({match.get('id')})")
            return

        label = f"исключение IPS {comment}"
        if not apply:
            self._record_planned(label)
            return
        payload = self.client.post(path, {"aliases": [alias_id], "comment": comment, "enabled": True})
        bypass_id = self._created_id(payload, "bypass", path)
        self._record_created(
            f"исключение IPS {comment} ({bypass_id})",
            _Rollback("исключение IPS", "DELETE", f"{path}/{quote(bypass_id)}"),
        )

    def _hw_get_optional(self, path: str) -> Any | None:
        """GET an OPTIONAL hardware-filtering endpoint: absent (404) → None.

        Older NGFW releases do not expose the section at all; that is a normal
        condition for this tool, not an error.
        """
        try:
            return self.client.get(path)
        except ApiError as exc:
            if "не поддерживает документированный endpoint" in str(exc):
                return None
            raise

    def _ensure_hw_rules(self, apply: bool) -> None:
        """Prefix-owned hardware-filtering rules in all three IP lists.

        The ACTIVE MODE is never changed: switching it is a box-wide setting far
        beyond adding prefixed rows. The current mode is reported instead so the
        operator knows which list the trace will actually evaluate.
        """
        settings = self._hw_get_optional("/firewall/hw_settings")
        if settings is None:
            self._warn("Аппаратная фильтрация не поддерживается этим NGFW (endpoint отсутствует); правила пропущены.")
            return
        mode = settings.get("mode") if isinstance(settings, dict) else None
        if mode:
            self.emit(f"[ACTIVE]  аппаратная фильтрация: режим {mode!r} (оценивается только его список)")
        else:
            self._warn("NGFW не сообщил режим аппаратной фильтрации; правила всё равно будут добавлены.")

        specs = [
            ("hw_rules_src_ip", {"source_ip": HW_SRC_TEST_IP}, f"HW src {HW_SRC_TEST_IP}"),
            ("hw_rules_dst_ip", {"destination_ip": HW_DST_TEST_IP}, f"HW dst {HW_DST_TEST_IP}"),
            (
                "hw_rules_src_dst_ip",
                {"source_ip": HW_PAIR_SRC_IP, "destination_ip": HW_PAIR_DST_IP},
                f"HW pair {HW_PAIR_SRC_IP}>{HW_PAIR_DST_IP}",
            ),
        ]
        for endpoint, fields, suffix in specs:
            path = f"/firewall/{endpoint}"
            listing = self._hw_get_optional(path)
            if listing is None:
                self._warn(f"Endpoint {path} отсутствует; правило пропущено.")
                continue
            rules = self._as_list(listing, path)
            comment = self._comment(suffix)
            matches = [item for item in rules if item.get("comment") == comment]
            if matches:
                match = matches[0]
                if any(str(match.get(key)) != value for key, value in fields.items()):
                    raise ConflictError(f"Аппаратное правило {comment!r} существует с другим адресом")
                self._record_reused(f"аппаратное правило {comment} ({match.get('id')})")
                continue

            label = f"аппаратное правило {comment}"
            if not apply:
                self._record_planned(label)
                continue
            payload = self.client.post(path, {**fields, "comment": comment, "enabled": True})
            rule_id = self._created_id(payload, "hw_rule", path)
            self._record_created(
                f"аппаратное правило {comment} ({rule_id})",
                _Rollback("аппаратное правило", "DELETE", f"{path}/{quote(rule_id)}"),
            )

    def _ensure_dns_zone(self, apply: bool) -> None:
        path = "/dns/zones/forward"
        zones = self._as_list(self.client.get(path), path)
        name = "stuck-dns.test"
        comment = self._comment("DNS forward test zone")
        matches = [item for item in zones if item.get("name") == name]
        if matches:
            match = matches[0]
            if set(match.get("servers") or []) != {"192.0.2.53"}:
                raise ConflictError(f"DNS-зона {name!r} уже существует с другими серверами")
            self._record_reused(f"DNS forward-zone {name} ({match.get('id')})")
            return

        label = f"DNS forward-zone {name} → 192.0.2.53"
        if not apply:
            self._record_planned(label)
            return
        payload = self.client.post(
            path,
            {
                "name": name,
                "enabled": True,
                "servers": ["192.0.2.53"],
                "comment": comment,
            },
        )
        zone_id = self._created_id(payload, "dns_zone", path)
        self._record_created(
            f"DNS forward-zone {name} ({zone_id})",
            _Rollback("DNS forward-zone", "DELETE", f"{path}/{quote(zone_id)}"),
        )

    def _check_modules(self, apply: bool) -> None:
        checks = [
            ("Межсетевой экран", "/firewall/state", None),
            ("Контент-фильтр", "/content-filter/state", "/content-filter/state"),
            ("IPS", "/ips/state", "/ips/state"),
        ]
        for name, get_path, patch_path in checks:
            state = self.client.get(get_path)
            if not isinstance(state, dict) or not isinstance(state.get("enabled"), bool):
                raise ApiError(f"NGFW вернул неожиданное состояние модуля {name}")
            if state["enabled"]:
                self.emit(f"[ACTIVE]  модуль {name}")
                continue
            if not self.options.enable_modules:
                self._warn(
                    f"Модуль {name} выключен; связанные сценарии не проявятся. "
                    "Для документированных CF/IPS можно добавить --enable-modules."
                )
                continue
            if patch_path is None:
                self._warn(
                    "Межсетевой экран выключен, а PATCH состояния отсутствует в "
                    "предоставленной документации; состояние не изменено."
                )
                continue
            label = f"включение модуля {name}"
            if not apply:
                self._record_planned(label)
                continue
            self.client.patch(patch_path, {"enabled": True})
            self._record_created(
                label,
                _Rollback(name, "PATCH", patch_path, {"enabled": False}),
            )

    @staticmethod
    def _rule_parent_id(rules: list[dict[str, Any]]) -> str:
        for rule in rules:
            value = rule.get("parent_id")
            if isinstance(value, str) and value:
                return value
        return ROOT_VCE_GROUP_ID

    @staticmethod
    def _insert_first_params(rules: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not rules or rules[0].get("id") is None:
            return None
        return {"anchor_item_id": rules[0]["id"], "insert_after": "false"}

    @staticmethod
    def _address_tokens(blocks: Any) -> set[str]:
        if not isinstance(blocks, list):
            return set()
        result: set[str] = set()
        for block in blocks:
            if isinstance(block, dict) and isinstance(block.get("addresses"), list):
                result.update(str(value) for value in block["addresses"])
        return result

    @staticmethod
    def _content_filter_alias_tokens(rule: dict[str, Any]) -> set[str]:
        legacy = rule.get("aliases")
        if isinstance(legacy, list):
            return {str(value) for value in legacy}

        blocks = rule.get("src_aliases")
        if not isinstance(blocks, list):
            return set()
        result: set[str] = set()
        for block in blocks:
            if isinstance(block, dict) and isinstance(block.get("aliases"), list):
                result.update(str(value) for value in block["aliases"])
        return result

    def _show_test_matrix(self) -> None:
        self.emit("\n== САЙТЫ И АДРЕСА ДЛЯ ПРОВЕРКИ В STUCK UI ==")
        rows = [
            ("example.com", "базовый сценарий; созданные правила не блокируют"),
            ("cf-block.example", "Контент-фильтр: deny для тестового пользователя"),
            (
                "cf-redirect.example",
                "Контент-фильтр: redirect на https://example.com/",
            ),
            ("example.org", "Межсетевой экран: drop для тестового пользователя"),
            ("203.0.113.10", "Межсетевой экран: reject для тестового пользователя"),
            (
                f"{FW_PORT_TEST_IP}:{FW_PORT_TEST_PORT}",
                "Межсетевой экран: drop по точному TCP-порту (первое правило)",
            ),
            (
                f"{FW_PORT_TEST_IP}:443",
                "Межсетевой экран: accept следующим более общим правилом",
            ),
            ("192.0.2.30", "IPS bypass (виден только при включенном IPS)"),
            (
                f"источник {HW_SRC_TEST_IP}",
                "Аппаратная фильтрация: drop при режиме src-ip (выберите этот IP источника)",
            ),
            (
                HW_DST_TEST_IP,
                "Аппаратная фильтрация: drop при режиме dst-ip",
            ),
            (
                f"{HW_PAIR_SRC_IP} → {HW_PAIR_DST_IP}",
                "Аппаратная фильтрация: drop при режиме src-and-dst-ip (нужна вся пара)",
            ),
        ]
        if self.options.include_dns:
            rows.append(
                (
                    "любое-имя.stuck-dns.test",
                    "DNS: имя попадает в локальную forward-зону — STUCK покажет её на стадии DNS",
                )
            )
        for value, expected in rows:
            self.emit(f"  - {value:<30} {expected}")
        self.emit(f"Для ограниченных сценариев выберите пользователя {self.options.test_user_login!r} в форме STUCK.")

    def _rollback(self) -> None:
        if not self._rollbacks:
            return
        self.emit("\n[ROLLBACK] Ошибка: удаляю только ресурсы, созданные этим запуском")
        for action in reversed(self._rollbacks):
            try:
                if action.method == "DELETE":
                    self.client.delete(action.path)
                elif action.method == "PATCH" and action.body is not None:
                    self.client.patch(action.path, action.body)
                self.emit(f"[ROLLED BACK] {action.description}")
            except NgfwToolError as exc:  # best effort; preserve original failure
                self.emit(f"[ROLLBACK FAILED] {action.description}: {exc}")
