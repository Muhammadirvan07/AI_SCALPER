# Windows Dependency Lock

`requirements.txt` adalah manifest development dan boleh memuat sumber proxy
seperti `yfinance`. File itu tidak boleh diwariskan oleh runtime live.
`requirements-live-windows.txt` adalah satu-satunya manifest direct pin untuk
build release Windows yang boleh digunakan di VPS, dan diikat oleh:

- `pylock.windows-cp312.toml`: versi dan artefak wheel exact;
- `vendor/windows-cp312-install-manifest.json`: digest file-tree yang diturunkan
  dari byte wheel terpilih, bukan dari `RECORD` yang sudah terpasang;
- `vendor/windows-cp312-dependency-sbom.cdx.json`: CycloneDX 1.6 deterministic
  untuk tepat 14 package runtime dan satu wheel bootstrap `pip`;
- `requirements-windows-bootstrap.lock.txt` dan
  `requirements-windows-cp312.lock.txt`: exact version dan hash wheel untuk
  instalasi offline;
- wheel vendored `pip==26.1.2` dan `ta==0.11.0`.

Target dikunci ke Windows x86-64, CPython 3.12, dan
`MetaTrader5==5.0.5735` wheel `cp312-cp312-win_amd64`. Seluruh file di atas
ikut dihitung dalam `dependency_lock_sha256` forward contract.

SBOM tidak memiliki timestamp atau random serial. Komponen diurutkan berdasarkan
nama package ternormalisasi dan mengikat exact name, version, PyPI purl, role
runtime/bootstrap, filename wheel, size, serta SHA-256 wheel. Path, size, dan
SHA-256 byte SBOM sendiri diikat oleh `dependency-sbom` pada
`[tool.ai_scalper]` di pylock. Validator membangun ulang dokumen expected dari
lock dan install manifest, lalu menolak missing file, hash drift, semantic
rewrite, package tambahan/hilang, atau encoding noncanonical.

## Menyiapkan wheelhouse pada host yang terhubung internet

Jalankan sebagai release step terpisah. Wheel disimpan di luar repository dan
kemudian disalin ke VPS:

```powershell
python -B .\build_windows_wheel_manifest.py `
  --lock .\pylock.windows-cp312.toml `
  --wheel-dir .\release-wheelhouse `
  --output .\runtime_state\windows-manifest-check.json `
  --download
```

Builder hanya menerima `files.pythonhosted.org` untuk wheel remote, lalu
memverifikasi size, SHA-256, kelengkapan `RECORD`, byte setiap anggota ZIP,
Windows path collision, dan file startup berbahaya. SHA-256 manifest hasil
check harus sama dengan manifest committed. Jangan mengganti manifest
committed saat forward contract aktif.

## Instalasi offline pada Windows VPS

Gunakan venv release baru yang dibuat dengan `--without-pip`. Jangan bootstrap
dengan pip lama dari venv, jangan aktivasi environment, dan jangan memasang tool
development, test, `setuptools`, atau `wheel`. Dari root repository:

```powershell
python -m venv --without-pip .venv-release

.\.venv-release\Scripts\python.exe -I -S -B `
  .\verify_windows_dependency_lock.py `
  --require-current-runtime

.\.venv-release\Scripts\python.exe -I -S -B `
  .\bootstrap_windows_dependencies.py `
  --wheelhouse .\release-wheelhouse

.\.venv-release\Scripts\python.exe -I -S -B `
  .\verify_windows_dependency_lock.py `
  --require-current-runtime `
  --check-installed
```

Bootstrapper memverifikasi wheelhouse sebagai direktori flat dengan exact 15
wheel terpilih dan tanpa file tambahan. Ia kemudian menambahkan hanya
`pip-26.1.2-py3-none-any.whl` yang sudah terverifikasi ke path proses terisolasi,
menjalankan satu instalasi `--force-reinstall` dari dua hashed requirements,
menghapus seluruh console wrapper dependency, dan memverifikasi installed
wheel-tree. Pip lama yang mungkin ada di host tidak pernah diimpor.

Selama bootstrap, repository, lock, manifest, dan wheelhouse harus read-only
bagi service account serta tidak memiliki writer bersamaan. Bootstrapper
memeriksa ulang hash pip vendored tepat sebelum dan sesudah import; pip juga
memverifikasi hash setiap wheel saat instalasi.

Jika bootstrap gagal setelah mulai menulis environment, buang venv tersebut dan
buat ulang dari nol. Jangan mencoba melanjutkan environment parsial.

`--no-compile` diterapkan oleh bootstrapper. Validator menolak seluruh
`.pyc`/`.pyo`, termasuk entri `RECORD` tanpa hash. `python -I -S -B` wajib untuk
bootstrap, sealer, post-install verification, dan runtime:

- `-I` mengabaikan `PYTHONPATH` dan user environment;
- `-S` mencegah `.pth`, `sitecustomize.py`, dan site-packages berjalan sebelum
  verifikasi;
- `-B` mencegah pembuatan bytecode yang tidak terikat manifest.

Pip membuat console wrapper Windows yang byte-nya bergantung pada interpreter
path. Sealer menghapus seluruh wrapper dependency dan baris `RECORD`-nya.
Venv release yang masih memiliki `pip.exe`, `normalizer.exe`, `pygmentize.exe`,
atau wrapper dependency lain ditolak. Hanya file inti venv seperti
`python.exe`, `pythonw.exe`, dan activation scripts yang boleh tersisa di
`Scripts`.

## Pemeriksaan post-install

Validator mensyaratkan:

- set distribution exact: 14 package runtime ditambah hanya `pip==26.1.2`;
- setiap file wheel sesuai tree digest dari wheel asli;
- `INSTALLER` tepat `pip\n` dan `REQUESTED` kosong;
- tidak ada `direct_url.json`, `origin.json`, `RECORD.jws`, `RECORD.p7s`,
  `.pth`, `sitecustomize.py`, `usercustomize.py`, bytecode, symlink/reparse
  point, collision case-insensitive, file site-packages tanpa owner, atau
  console wrapper yang belum diseal;
- rewrite package plus rewrite installed `RECORD` tetap gagal karena tree digest
  berasal dari wheel terkunci;
- manifest, hashed requirements, pip wheel, dan ta wheel tidak berubah.

Set package runtime dikunci minimal. `yfinance` beserta dependency jaringan
Yahoo tidak boleh muncul di direct manifest, lock, wheelhouse, atau installed
environment live. Sumber proxy tersebut tetap hanya tersedia melalui
`requirements.txt` untuk development/legacy diagnostics.

Runtime shadow harus dimulai dengan:

```powershell
.\.venv-release\Scripts\python.exe -I -S -B .\run_xm_shadow_once.py
```

Runner memverifikasi environment, menambahkan hanya path `site-packages` yang
ada di receipt, memulihkan prefix venv tanpa mengimpor `site`, lalu menambahkan
repository root terkontrol. Startup table SQLite bersifat append-only; kegagalan
guard tetap `HOLD` dan order capability tetap `DISABLED`.

## Regenerasi

Regenerasi hanya sebagai perubahan release terpisah:

```powershell
uv pip compile .\requirements-live-windows.txt `
  --python-platform x86_64-pc-windows-msvc `
  --python-version 3.12 `
  --format pylock.toml `
  --output-file .\pylock.windows-cp312.toml

python -B .\build_windows_wheel_manifest.py `
  --lock .\pylock.windows-cp312.toml `
  --wheel-dir .\release-wheelhouse `
  --output .\vendor\windows-cp312-install-manifest.json `
  --bootstrap-requirements-output .\requirements-windows-bootstrap.lock.txt `
  --runtime-requirements-output .\requirements-windows-cp312.lock.txt `
  --download

python -I -S -B .\build_windows_dependency_sbom.py `
  --lock .\pylock.windows-cp312.toml `
  --output .\vendor\windows-cp312-dependency-sbom.cdx.json
```

Setelah resolver, kembalikan metadata target dan binding wheel bootstrap pada
`[tool.ai_scalper]`. Perbarui juga binding `dependency-sbom` dengan exact path,
size, dan SHA-256 yang dicetak generator. Build wheel `ta` reproducibly,
jalankan kedua generator sedikitnya dua kali, lalu pastikan pemeriksaan berikut
lulus tanpa menulis ulang artifact:

```powershell
python -I -S -B .\build_windows_dependency_sbom.py `
  --lock .\pylock.windows-cp312.toml `
  --output .\vendor\windows-cp312-dependency-sbom.cdx.json `
  --check
```

Hanya terima hasil jika seluruh hash identik. Jalankan validator, tes
adversarial, dependency audit, dan clean-checkout verification sebelum commit.
Sesudah lock/SBOM final, jalankan collection dan offline verification sesuai
[Windows Release Vulnerability Audit](WINDOWS_VULNERABILITY_AUDIT.md); tidak
adanya receipt OSV yang fresh dan valid harus tetap memblokir release.
