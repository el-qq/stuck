"""Command-line interface for the isolated NGFW test-data seeder."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

from .client import NgfwApiClient
from .errors import InputError, NgfwToolError
from .seeder import NgfwTestDataSeeder, SeedOptions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.ngfw_testdata",
        description=(
            "Идемпотентно создать изолированные объекты, пользователя и правила "
            "для проверки STUCK UI. Для просмотра плана используйте --dry-run."
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="DOMAIN_OR_IP:PORT",
        help="NGFW без схемы и пути, например 192.168.100.11:8443",
    )
    parser.add_argument(
        "--login",
        help="логин администратора NGFW; если не указан, будет запрошен",
    )
    parser.add_argument(
        "--password",
        help=(
            "пароль администратора; безопаснее не указывать и ввести в скрытом prompt либо задать NGFW_ADMIN_PASSWORD"
        ),
    )
    parser.add_argument(
        "--prefix",
        default="STUCK TEST",
        help="префикс всех создаваемых ресурсов (по умолчанию: %(default)s)",
    )
    parser.add_argument(
        "--parent-group-id",
        default="group.id.1",
        help="родитель локальной тестовой группы (по умолчанию: %(default)s)",
    )
    parser.add_argument(
        "--test-user-login",
        default="stuck-test-user",
        help="логин создаваемого пользователя (по умолчанию: %(default)s)",
    )
    parser.add_argument(
        "--test-user-password",
        help=(
            "пароль тестового пользователя; если не задан, будет "
            "сгенерирован (также поддерживается NGFW_TEST_USER_PASSWORD)"
        ),
    )
    parser.add_argument(
        "--include-dns",
        action="store_true",
        help="добавить изолированную forward-zone stuck-dns.test → 192.0.2.53",
    )
    parser.add_argument(
        "--enable-modules",
        action="store_true",
        help=(
            "включить выключенные CF/IPS через документированные PATCH API; "
            "это глобальное изменение, по умолчанию не выполняется"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="только показать план без изменения конфигурации NGFW",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--verify-tls",
        action="store_true",
        help="строго проверять TLS-сертификат по системному хранилищу CA",
    )
    tls.add_argument(
        "--ca-bundle",
        type=Path,
        help="путь к доверенному CA bundle для TLS-проверки NGFW",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="таймаут одного NGFW-запроса в секундах (по умолчанию: %(default)s)",
    )
    return parser


def _generated_test_password() -> str:
    # Known character classes + random URL-safe tail satisfy typical lab policy.
    return "St9!" + secrets.token_urlsafe(18)


def _admin_login(argument: str | None) -> str:
    if argument and argument.strip():
        return argument.strip()
    try:
        login = input("Логин администратора NGFW: ").strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise InputError(
            "Не удалось прочитать логин интерактивно",
            hint="Для автоматического запуска задайте --login.",
        ) from exc
    if not login:
        raise InputError(
            "Логин администратора NGFW не может быть пустым",
            hint="Введите логин или задайте --login.",
        )
    return login


def _admin_password(argument: str | None) -> str:
    if argument:
        return argument
    environment = os.environ.get("NGFW_ADMIN_PASSWORD")
    if environment:
        return environment
    try:
        return getpass.getpass("Пароль администратора NGFW: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise InputError(
            "Не удалось прочитать пароль интерактивно",
            hint="Задайте переменную NGFW_ADMIN_PASSWORD или --password.",
        ) from exc


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        apply = not args.dry_run
        if args.ca_bundle is not None and not args.ca_bundle.is_file():
            raise InputError(f"CA bundle не найден: {args.ca_bundle}")

        admin_login = _admin_login(args.login)
        admin_password = _admin_password(args.password)
        configured_test_password = args.test_user_password or os.environ.get("NGFW_TEST_USER_PASSWORD") or ""
        generated = False
        if apply and not configured_test_password:
            configured_test_password = _generated_test_password()
            generated = True

        if args.ca_bundle is not None:
            verify: bool | str | Path = args.ca_bundle
        elif args.verify_tls:
            verify = True
        else:
            verify = False
            print(
                "[WARNING] TLS-сертификат NGFW не проверяется. "
                "Для строгой проверки используйте --verify-tls или --ca-bundle.",
                file=sys.stderr,
            )

        options = SeedOptions(
            prefix=args.prefix,
            parent_group_id=args.parent_group_id,
            test_user_login=args.test_user_login,
            test_user_password=configured_test_password,
            include_dns=args.include_dns,
            enable_modules=args.enable_modules,
        )
        with NgfwApiClient(
            args.target,
            admin_login,
            admin_password,
            verify=verify,
            timeout=args.timeout,
        ) as client:
            print(f"[OK] Авторизация на {client.base_url} выполнена")
            summary = NgfwTestDataSeeder(client, options).seed(apply=apply)

        print("\n== ИТОГ ==")
        print(f"Создано: {len(summary.created)}")
        print(f"Уже существовало и переиспользовано: {len(summary.reused)}")
        print(f"Запланировано без изменения: {len(summary.planned)}")
        print(f"Предупреждений: {len(summary.warnings)}")
        if generated and any("пользователь" in item for item in summary.created):
            print(f"[SECRET] Пароль нового тестового пользователя {args.test_user_login}: {configured_test_password}")
            print("Сохраните его сейчас: повторно получить пароль через API нельзя.")
        if args.dry_run:
            print("Это был только план. Для применения уберите флаг --dry-run.")
        return 0
    except NgfwToolError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        if exc.hint:
            print(f"[HINT]  {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\n[CANCELLED] Операция прервана пользователем.", file=sys.stderr)
        return 130
