# sealbox 🔐

**Мини-сейф для секретов**: шифруйте `.env`, ключи и любые файлы одним паролем.
Результат — компактный JSON-«бокс», который можно спокойно коммитить в git.

- **AES-256-GCM** — проверенная аутентифицированная криптография (библиотека `cryptography`)
- **scrypt** (из stdlib) или **Argon2id** (опционально) — memory-hard вывод ключа из пароля
- Свежие **salt + nonce** при каждой упаковке, защита от подмены данных (GCM tag)
- Никаких паролей в аргументах командной строки — только файл, переменная окружения или скрытый ввод
- Атомарная запись, права `0600` на расшифрованные файлы, zero-dependency кроме `cryptography`
- CLI + Python API, типизация, тесты

```text
$ sealbox seal secrets.env        # -> secrets.env.sealbox (спросит пароль дважды)
$ sealbox open secrets.env.sealbox  # -> secrets.env
$ sealbox env secrets.env.sealbox -- python app.py   # секреты в os.environ
```

## Установка

```bash
pip install sealbox            # из исходников: pip install .
pip install 'sealbox[argon2]'  # + Argon2id вместо scrypt (рекомендуется)
```

Требуется Python 3.9+.

## CLI

| Команда | Что делает |
|---|---|
| `sealbox seal FILE [-o OUT] [--algo scrypt\|argon2id] [-f]` | Зашифровать файл (по умолчанию `FILE.sealbox`) |
| `sealbox open BOX [-o OUT] [-f]` | Расшифровать в файл (права `0600`) |
| `sealbox show BOX` | Вывести содержимое в stdout |
| `sealbox env BOX -- CMD [ARGS...]` | Запустить команду, подставив `KEY=VALUE` из бокса в окружение |
| `sealbox rotate BOX` | Сменить пароль (KDF обновляется до текущего умолчания) |
| `sealbox inspect BOX` | Метаданные без пароля (KDF, размеры) |

**Как передаётся пароль** (по приоритету, в аргументах — никогда):

1. `--passphrase-file FILE` — первая строка файла;
2. переменная окружения `SEALBOX_PASSPHRASE` (удобно в CI);
3. скрытый интерактивный ввод (`seal` спрашивает дважды).

Для CI это выглядит так:

```bash
echo "$SEALBOX_PASS" > /tmp/pass.txt
sealbox open secrets.env.sealbox --passphrase-file /tmp/pass.txt
shred -u /tmp/pass.txt
```

CLI доступен и как модуль: `python -m sealbox …`.

## Python API

```python
import sealbox

# байты
box = sealbox.seal_bytes(b"TOKEN=s3cr3t", passphrase)
assert sealbox.open_bytes(box, passphrase) == b"TOKEN=s3cr3t"

# файлы
sealbox.seal_file("secrets.env", passphrase=passphrase)      # -> secrets.env.sealbox
sealbox.open_file("secrets.env.sealbox", passphrase=passphrase)  # -> secrets.env

# .env-переменные прямо в os.environ
sealbox.load_sealed_env("secrets.env.sealbox", passphrase)

# запуск дочернего процесса с секретами в окружении
sealbox.run_with_sealed_env("secrets.env.sealbox", ["python", "app.py"], passphrase)

# метаданные (пароль не нужен)
print(sealbox.inspect_file("secrets.env.sealbox"))
```

Исключения: `WrongPassphrase` (неверный пароль либо данные изменены — AES-GCM
не различает эти случаи), `CorruptedBox`, `UnsupportedFormat`, общий предок
`SealboxError`.

## Формат бокса

UTF-8 JSON с base64-полями, ключи отсортированы:

```json
{
 "ciphertext": "…(AES-256-GCM, последние 16 байт — тег)…",
 "format": "sealbox",
 "kdf": {"algorithm": "scrypt", "n": 32768, "p": 1, "r": 8},
 "nonce": "…12 байт…",
 "salt": "…16 байт…",
 "version": 1
}
```

- AAD = `"sealbox/1"` привязывает шифротекст к версии формата.
- Параметры KDF хранятся в боксе, поэтому смена умолчаний в будущих версиях
  не ломает старые файлы (а боксы с чрезмерными параметрами отклоняются).
- Имя исходного файла не хранится — метаданных минимум.

## Модель угроз

**Защищает от:** утечки секретов через git, бэкапы, случайно расшаренные папки,
скриншоты/копии зашифрованного файла — без пароля это шум.

**НЕ защищает от:** кейлоггеров и скомпрометированной ОС, подбора слабого
пароля (KDF замедляет перебор, но не заменяет стойкий пароль), потери пароля
(восстановления нет), а также от того, что plaintext валяется рядом с боксом.

Пароль в CLI-аргументах не принимается осознанно: аргументы видны в истории
shell и в `/proc/<pid>/cmdline`.

## Разработка

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,argon2]'
pytest
```

## Roadmap

- [ ] `sealbox seal --shred` — затирать plaintext после упаковки (best-effort)
- [ ] `sealbox seal-dir` — упаковка каталога (tar + шифрование)
- [ ] Поддержка нескольких получателей (public-key sealing)
- [ ] `sealbox audit` — проверка, не попал ли plaintext в git

## Лицензия

MIT — см. [LICENSE](LICENSE).
