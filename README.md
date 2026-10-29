
ZyrexAi License Server
Server lisensi berbasis serial perangkat (ro.serialno) untuk modul ZyrexAi.
Berjalan di Deno Deploy + Deno KV (gratis, tanpa kartu kredit).
Perangkat yang serialnya belum kamu daftarkan tidak bisa menjalankan modul.
File
main.ts — seluruh kode server
deno.json — konfigurasi Deno
Deploy (sekali saja)
Database: console.deno.com > Databases > Provision Database > Deno KV > beri nama (mis. zyrex-db) > simpan.
Repo: upload main.ts, deno.json, dan README ini ke repo GitHub private (mis. zyrex-server).
App: + New App > pilih repo > entrypoint main.ts (tanpa build command).
Environment variables:# zyrex-server
