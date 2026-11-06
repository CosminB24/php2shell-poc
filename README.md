# php2shell PoC — CVE-2026-109618 / CVE-2026-109619

Working proof-of-concept against `php:8.4.26-apache` (Debian 13 trixie,
Apache prefork single-worker, mod_php, PHP 8.4.26 NTS).

## Chain

1. **Stage 1 — Zend MM chunk base leak.** Worker rotation via OOM abort, then a
   forged 48-byte session value (len `0x1000`) makes `Set-Cookie` over-read the
   heap back to the Zend MM chunk header. `Set-Cookie` is not bounded by
   `memory_limit`, so the read succeeds even though the request OOMs.
2. **Stage 2 — `libphp.so` base leak.** A 983-field request with the 32-byte
   split at index 406 (`16 x 16` bytes) puts a cut-off 32-byte value right on
   `zend_reference::val.value` of the staged reference, so the following
   `zval_ptr_dtor` leaks the reference's `pDestructor` (a `libphp` text
   pointer) through the same `Set-Cookie` channel.
3. **Stage 3 — RCE.** The OOM leaves `PS(http_session_vars)` / `PS(id)`
   dangling. The carrier request reoccupies the still-live `zend_reference`
   with `(rc=1, type=1, value=htdata)`, pins a fake 167-byte `HashTable` whose
   `pDestructor` is `zif_system`, and the next `php_session_track_init()`
   destroys it: `zif_system(cmd)`.

ASLR is bypassed by stages 1-2; stage 3 uses chunk-relative offsets only
(`zif_system = 0x465370`, `zval_ptr_dtor = 0x65eb60`, `htdata = 0x690D8`).

## Why the lab config matters

The stage-3 heap grooming is **extremely** sensitive to the allocation
sequence. This PoC only works when the lab matches the verified reference
(`3em0/php2shell`) exactly:

| Setting | Value | Why |
|---|---|---|
| `memory_limit` | `8M` | OOM must fire at the same point in the field parser |
| `post_max_size` / `upload_max_filesize` | `64M` | the 12 MB field must reach PHP |
| `expose_php` | **unset (On)** | the `X-Powered-By` header allocates in the heap *before* session-init and shifts the grooming |
| `session.upload_progress.cleanup` | `On` | must not be `0` |
| `session.use_only_cookies` | **unset (On)** | setting it to `0` changes `PS(id)` size and breaks the grooming |
| MPM prefork | `ServerLimit 1`, `MaxConnectionsPerChild 0`, `KeepAlive Off` | single deterministic worker |

Changing `memory_limit` to `16M`, `expose_php` to `0`, or `post_max_size` to
`32M` all reproduced the same failure: `ps_files_open` on a corrupted
`PS(id)`, then `zend_mm_panic` before the destructor fired.

## Run

```bash
docker compose up -d
python3 exploit.py http://127.0.0.1:8088/ "id>/tmp/pwn"
```

Expected:

```
[+] chunk base = 0x...
[+] libphp base = 0x...
[+] RCE confirmed on attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![php2shell RCE proof](docs/proof.png)

The command is `system(3)` via `/bin/sh -c`, limited to 14 bytes by the
167-byte carrier. Use an **absolute** proof path (`/tmp/...`): the worker's
cwd is `/`, so a relative path would land outside any served directory.

### Proof read-back

`exploit.py` auto-detects it, in order:

1. local `docker exec` (default container `php2shell-target`) — works when the
   exploit runs on the lab host;
2. `ssh <user>@<target>` + `docker exec` — works remotely with SSH keys
   (override with `--proof-ssh user@host`, default user `--ssh-user kali`);
3. plain HTTP at `<target>/<proof path>` — only if the command wrote into the
   webroot.

## Files

- `exploit.py` — the PoC (raw-socket HTTP client, standard library only)
- `php.ini` — lab PHP config (must match the table above)
- `apache.conf` — single-worker prefork MPM
- `docker-compose.yml`, `Dockerfile` — the lab (`php:8.4.26-apache`)
- `webroot/index.php` — target page
- `docs/proof.png` — screenshot of a successful run

## Notes

- The offsets are for the official `php:8.4.26-apache` image (Debian 13,
  glibc 2.41-12+deb13u4). Another patch level needs fresh offsets; the
  grooming constants (`htdata`, `stage1_n`, `stage2_t`) are build/config
  specific, so a different target needs recalibration.
- Stage 3 is a one-shot heap-grooming primitive: it is not designed to survive
  concurrent traffic, and a failed attempt needs a worker rotation (handled by
  the exploit's retry loop).
- Lab PoC for defensive research. The vulnerable build is fixed in later
  patch levels.
