#include "storage/storage.h"

#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "vault/entry.h"

/* ---------------------------------------------------------------- parámetros */

/* Costo del KDF. Se pueden sobrescribir al compilar (los tests usan valores bajos). */
#ifndef STORAGE_KDF_OPSLIMIT
#define STORAGE_KDF_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#endif
#ifndef STORAGE_KDF_MEMLIMIT
#define STORAGE_KDF_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE
#endif

/* Topes al LEER un header: un archivo manipulado no puede pedir costos absurdos. */
#define MAX_OPSLIMIT   20ULL
#define MAX_MEMLIMIT   (1ULL << 30)   /* 1 GiB */

#define KEY_LEN     crypto_aead_xchacha20poly1305_ietf_KEYBYTES    /* 32 */
#define NONCE_LEN   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   /* 24 */
#define TAG_LEN     crypto_aead_xchacha20poly1305_ietf_ABYTES      /* 16 */
#define SALT_LEN    crypto_pwhash_SALTBYTES                        /* 16 */
#define WRAP_LEN    (NONCE_LEN + KEY_LEN + TAG_LEN)                /* 72 */

/* Padding del contenido: el tamaño del archivo solo revela "cuántos bloques". */
#define PAD_BLOCK   4096U

/* Límites del contenido (se validan al leer: el archivo puede estar manipulado). */
#define MAX_ENTRIES    10000U
#define MAX_FIELD_LEN  (1U << 20)
#define MAX_FILE_SIZE  (64U * 1024U * 1024U)

#define FORMAT_VERSION 1U

/* ------------------------------------------------------------ layout del header
 *
 *   0  magic "PWMGR"            5
 *   5  version                  1
 *   6  opslimit (u64 LE)        8
 *  14  memlimit (u64 LE)        8
 *  22  salt                    16
 *  38  master_wrap             72   (nonce || AEAD(KEK_master, vault_key))
 * 110  recovery_wrap           72   (nonce || AEAD(recovery_key, vault_key))
 * 182  -- fin del header --
 *      body: nonce(24) || AEAD(vault_key, contenido con padding)
 *
 * Datos asociados (AD) de todos los AEAD: magic || version (6 bytes).
 * Los parámetros del KDF y el salt no necesitan AD: si se alteran, la KEK
 * derivada cambia y el unwrap falla.
 */
#define MAGIC          "PWMGR"
#define MAGIC_LEN      5U
#define AD_LEN         6U
#define OFF_VERSION    5U
#define OFF_OPS        6U
#define OFF_MEM        14U
#define OFF_SALT       22U
#define OFF_MASTER     (OFF_SALT + SALT_LEN)         /* 38 */
#define OFF_RECOVERY   (OFF_MASTER + WRAP_LEN)       /* 110 */
#define HEADER_LEN     (OFF_RECOVERY + WRAP_LEN)     /* 182 */

struct storage {
  char     *path;
  uint64_t  opslimit;
  uint64_t  memlimit;
  uint8_t   salt[SALT_LEN];
  uint8_t   master_wrap[WRAP_LEN];
  uint8_t   recovery_wrap[WRAP_LEN];
  uint8_t  *vault_key;               /* sodium_malloc: KEY_LEN bytes */
};

/* --------------------------------------------------------------- util binaria */

static void put_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v & 0xFFU);
  p[1] = (uint8_t) ((v >> 8) & 0xFFU);
  p[2] = (uint8_t) ((v >> 16) & 0xFFU);
  p[3] = (uint8_t) ((v >> 24) & 0xFFU);
}

static uint32_t get_u32(const uint8_t *p)
{
  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
         ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void put_u64(uint8_t *p, uint64_t v)
{
  for (unsigned i = 0; i < 8; i++)
    p[i] = (uint8_t) ((v >> (8U * i)) & 0xFFU);
}

static uint64_t get_u64(const uint8_t *p)
{
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t) p[i] << (8U * i);
  return v;
}

/* ---------------------------------------------------------------- archivos */

/* Lee el archivo completo. Retorna buffer malloc'd (el contenido está cifrado). */
static int read_file(const char *path, uint8_t **buf, size_t *len)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return STORAGE_ERR_IO;

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uintmax_t) st.st_size > MAX_FILE_SIZE) {
    close(fd);
    return STORAGE_ERR_IO;
  }

  size_t size = (size_t) st.st_size;
  uint8_t *b = malloc(size ? size : 1);
  if (b == NULL) { close(fd); return STORAGE_ERR_CRYPTO; }

  size_t got = 0;
  while (got < size) {
    ssize_t n = read(fd, b + got, size - got);
    if (n < 0) { free(b); close(fd); return STORAGE_ERR_IO; }
    if (n == 0) break;
    got += (size_t) n;
  }
  close(fd);

  *buf = b;
  *len = got;
  return STORAGE_OK;
}

/* Escritura atómica: tmp (0600) -> fsync -> rename -> fsync del directorio. */
static int write_file_atomic(const char *path, const uint8_t *data, size_t len)
{
  size_t plen = strlen(path);
  char *tmp = malloc(plen + 5);
  char *dircopy = strdup(path);
  if (tmp == NULL || dircopy == NULL) { free(tmp); free(dircopy); return STORAGE_ERR_CRYPTO; }
  memcpy(tmp, path, plen);
  memcpy(tmp + plen, ".tmp", 5);

  int rc = STORAGE_ERR_IO;
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) goto done;
  if (fchmod(fd, 0600) != 0) { close(fd); goto fail; }

  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, data + off, len - off);
    if (n < 0) { close(fd); goto fail; }
    off += (size_t) n;
  }
  if (fsync(fd) != 0) { close(fd); goto fail; }
  if (close(fd) != 0) goto fail;

  if (rename(tmp, path) != 0) goto fail;

  int dfd = open(dirname(dircopy), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) { (void) fsync(dfd); close(dfd); }
  rc = STORAGE_OK;
  goto done;

fail:
  unlink(tmp);
done:
  free(tmp);
  free(dircopy);
  return rc;
}

/* ------------------------------------------------------------------ claves */

static int derive_master_kek(uint8_t *kek, const char *master,
                             const uint8_t *salt, uint64_t ops, uint64_t mem)
{
  if (crypto_pwhash(kek, KEY_LEN, master, strlen(master), salt,
                    (unsigned long long) ops, (size_t) mem,
                    crypto_pwhash_ALG_ARGON2ID13) != 0)
    return STORAGE_ERR_CRYPTO;
  return STORAGE_OK;
}

static int wrap_key(uint8_t out[WRAP_LEN], const uint8_t *kek, const uint8_t *vault_key)
{
  uint8_t ad[AD_LEN];
  memcpy(ad, MAGIC, MAGIC_LEN);
  ad[MAGIC_LEN] = (uint8_t) FORMAT_VERSION;

  randombytes_buf(out, NONCE_LEN);
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(out + NONCE_LEN, NULL,
                                                 vault_key, KEY_LEN, ad, AD_LEN,
                                                 NULL, out, kek) != 0)
    return STORAGE_ERR_CRYPTO;
  return STORAGE_OK;
}

static int unwrap_key(uint8_t *vault_key, const uint8_t wrap[WRAP_LEN], const uint8_t *kek)
{
  uint8_t ad[AD_LEN];
  memcpy(ad, MAGIC, MAGIC_LEN);
  ad[MAGIC_LEN] = (uint8_t) FORMAT_VERSION;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(vault_key, NULL, NULL,
                                                 wrap + NONCE_LEN, KEY_LEN + TAG_LEN,
                                                 ad, AD_LEN, wrap, kek) != 0)
    return STORAGE_ERR_AUTH;
  return STORAGE_OK;
}

/* ------------------------------------------------------------------ header */

static void header_encode(const struct storage *s, uint8_t out[HEADER_LEN])
{
  memcpy(out, MAGIC, MAGIC_LEN);
  out[OFF_VERSION] = (uint8_t) FORMAT_VERSION;
  put_u64(out + OFF_OPS, s->opslimit);
  put_u64(out + OFF_MEM, s->memlimit);
  memcpy(out + OFF_SALT, s->salt, SALT_LEN);
  memcpy(out + OFF_MASTER, s->master_wrap, WRAP_LEN);
  memcpy(out + OFF_RECOVERY, s->recovery_wrap, WRAP_LEN);
}

static int header_decode(struct storage *s, const uint8_t *in, size_t len)
{
  if (len < HEADER_LEN + NONCE_LEN + TAG_LEN) return STORAGE_ERR_FORMAT;
  if (memcmp(in, MAGIC, MAGIC_LEN) != 0) return STORAGE_ERR_FORMAT;
  if (in[OFF_VERSION] != FORMAT_VERSION) return STORAGE_ERR_FORMAT;

  uint64_t ops = get_u64(in + OFF_OPS);
  uint64_t mem = get_u64(in + OFF_MEM);
  if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > MAX_OPSLIMIT) return STORAGE_ERR_FORMAT;
  if (mem < crypto_pwhash_MEMLIMIT_MIN || mem > MAX_MEMLIMIT) return STORAGE_ERR_FORMAT;

  s->opslimit = ops;
  s->memlimit = mem;
  memcpy(s->salt, in + OFF_SALT, SALT_LEN);
  memcpy(s->master_wrap, in + OFF_MASTER, WRAP_LEN);
  memcpy(s->recovery_wrap, in + OFF_RECOVERY, WRAP_LEN);
  return STORAGE_OK;
}

/* --------------------------------------------------------- (de)serialización
 *
 * Contenido (antes del padding), todo en little-endian y con largos prefijados:
 *   u32 version_formato | u32 next_id | u32 count
 *   por entrada: u32 id | (u32 len, bytes) site_name | password | notes
 * Nada de volcar structs: los punteros no sirven en disco y el padding del
 * compilador cambia entre plataformas.
 */

static size_t field_len(const char *s) { return s ? strlen(s) : 0; }

/* Retorna buffer sodium_malloc'd con el contenido YA con padding. */
static uint8_t *serialize_vault(const vault_t *v, size_t *padded_len)
{
  if (v->count > MAX_ENTRIES) return NULL;

  size_t len = 12;
  for (size_t i = 0; i < v->count; i++) {
    const entry_t *e = &v->entries[i];
    size_t a = field_len(e->site_name), b = field_len(e->password), c = field_len(e->notes);
    if (a > MAX_FIELD_LEN || b > MAX_FIELD_LEN || c > MAX_FIELD_LEN) return NULL;
    len += 4 + 4 + a + 4 + b + 4 + c;
  }

  size_t cap = len + PAD_BLOCK;
  uint8_t *buf = sodium_malloc(cap);
  if (buf == NULL) return NULL;

  uint8_t *p = buf;
  put_u32(p, FORMAT_VERSION);          p += 4;
  put_u32(p, (uint32_t) v->next_id);   p += 4;
  put_u32(p, (uint32_t) v->count);     p += 4;

  for (size_t i = 0; i < v->count; i++) {
    const entry_t *e = &v->entries[i];
    const char *fields[3] = { e->site_name, e->password, e->notes };

    put_u32(p, (uint32_t) e->id);
    p += 4;
    for (int f = 0; f < 3; f++) {
      size_t n = field_len(fields[f]);
      put_u32(p, (uint32_t) n);
      p += 4;
      if (n) memcpy(p, fields[f], n);
      p += n;
    }
  }

  if (sodium_pad(padded_len, buf, len, PAD_BLOCK, cap) != 0) {
    sodium_free(buf);
    return NULL;
  }
  return buf;
}

typedef struct { const uint8_t *p; size_t left; } reader_t;

static int rd_u32(reader_t *r, uint32_t *out)
{
  if (r->left < 4) return -1;
  *out = get_u32(r->p);
  r->p += 4;
  r->left -= 4;
  return 0;
}

static int rd_str(reader_t *r, char **out)
{
  uint32_t n;
  if (rd_u32(r, &n) != 0) return -1;
  if (n > MAX_FIELD_LEN || n > r->left) return -1;
  if (n && memchr(r->p, 0, n) != NULL) return -1;     /* '\0' embebido: inválido */

  char *s = malloc((size_t) n + 1);
  if (s == NULL) return -1;
  if (n) memcpy(s, r->p, n);
  s[n] = '\0';
  r->p += n;
  r->left -= n;
  *out = s;
  return 0;
}

/* Llena *out (debe estar vacío). Valida todo: el archivo puede estar manipulado. */
static int deserialize_vault(const uint8_t *buf, size_t len, vault_t *out)
{
  reader_t r = { buf, len };
  uint32_t version, next_id, count;

  if (rd_u32(&r, &version) != 0 || version != FORMAT_VERSION) return STORAGE_ERR_TAMPERED;
  if (rd_u32(&r, &next_id) != 0 || rd_u32(&r, &count) != 0) return STORAGE_ERR_TAMPERED;
  if (count > MAX_ENTRIES) return STORAGE_ERR_TAMPERED;

  vault_t tmp = {0};
  size_t cap = count ? count : 1;
  tmp.entries = calloc(cap, sizeof *tmp.entries);
  if (tmp.entries == NULL) return STORAGE_ERR_CRYPTO;
  tmp.capacity = cap;
  tmp.next_id = next_id;

  for (uint32_t i = 0; i < count; i++) {
    entry_t *e = &tmp.entries[i];
    uint32_t id;
    if (rd_u32(&r, &id) != 0) goto bad;
    e->id = id;
    tmp.count = i + 1;        /* desde acá, vault_free libera esta entrada */

    if (rd_str(&r, &e->site_name) != 0 ||
        rd_str(&r, &e->password) != 0 ||
        rd_str(&r, &e->notes) != 0)
      goto bad;

    if (id >= next_id) goto bad;
    for (uint32_t j = 0; j < i; j++)
      if (tmp.entries[j].id == id) goto bad;          /* IDs duplicados */
  }
  if (r.left != 0) goto bad;                          /* sobran bytes */

  *out = tmp;
  return STORAGE_OK;

bad:
  vault_free(&tmp);
  return STORAGE_ERR_TAMPERED;
}

/* -------------------------------------------------------------- API pública */

int storage_init(void)
{
  return sodium_init() < 0 ? STORAGE_ERR_CRYPTO : STORAGE_OK;
}

int storage_exists(const char *path)
{
  return path != NULL && access(path, F_OK) == 0;
}

const char *storage_strerror(int status)
{
  switch (status) {
    case STORAGE_OK:           return "ok";
    case STORAGE_ERR_IO:       return "could not read or write the vault file";
    case STORAGE_ERR_FORMAT:   return "not a valid vault file";
    case STORAGE_ERR_AUTH:     return "wrong password or recovery key (or the file header was modified)";
    case STORAGE_ERR_TAMPERED: return "vault contents are corrupted or were modified";
    case STORAGE_ERR_CRYPTO:   return "cryptographic or memory error";
    case STORAGE_ERR_EXISTS:   return "a vault file already exists at that path";
    case STORAGE_ERR_ARG:      return "invalid argument";
    default:                   return "unknown error";
  }
}

void storage_close(storage_t *s)
{
  if (s == NULL) return;
  if (s->vault_key) sodium_free(s->vault_key);
  free(s->path);
  sodium_memzero(s, sizeof *s);
  free(s);
}

static storage_t *storage_new(const char *path)
{
  storage_t *s = calloc(1, sizeof *s);
  if (s == NULL) return NULL;
  s->path = strdup(path);
  s->vault_key = sodium_malloc(KEY_LEN);
  if (s->path == NULL || s->vault_key == NULL) { storage_close(s); return NULL; }
  return s;
}

int storage_save(storage_t *s, const vault_t *vault)
{
  if (s == NULL || vault == NULL) return STORAGE_ERR_ARG;

  size_t plen;
  uint8_t *plain = serialize_vault(vault, &plen);
  if (plain == NULL) return STORAGE_ERR_CRYPTO;

  size_t blob_len = HEADER_LEN + NONCE_LEN + plen + TAG_LEN;
  uint8_t *blob = malloc(blob_len);       /* solo header y texto cifrado: no es secreto */
  if (blob == NULL) { sodium_free(plain); return STORAGE_ERR_CRYPTO; }

  header_encode(s, blob);

  uint8_t *nonce = blob + HEADER_LEN;
  randombytes_buf(nonce, NONCE_LEN);

  uint8_t ad[AD_LEN];
  memcpy(ad, MAGIC, MAGIC_LEN);
  ad[MAGIC_LEN] = (uint8_t) FORMAT_VERSION;

  int rc = STORAGE_OK;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(nonce + NONCE_LEN, NULL, plain, plen,
                                                 ad, AD_LEN, NULL, nonce,
                                                 s->vault_key) != 0)
    rc = STORAGE_ERR_CRYPTO;

  sodium_free(plain);                      /* sodium_free borra el contenido */

  if (rc == STORAGE_OK)
    rc = write_file_atomic(s->path, blob, blob_len);

  free(blob);
  return rc;
}

int storage_create(storage_t **out, const char *path, const char *master,
                   char recovery_hex[STORAGE_RECOVERY_HEX_LEN + 1])
{
  if (out == NULL || path == NULL || master == NULL || master[0] == '\0' ||
      recovery_hex == NULL)
    return STORAGE_ERR_ARG;
  *out = NULL;

  if (storage_exists(path)) return STORAGE_ERR_EXISTS;

  storage_t *s = storage_new(path);
  uint8_t *kek = sodium_malloc(KEY_LEN);
  uint8_t *rkey = sodium_malloc(KEY_LEN);
  int rc = STORAGE_ERR_CRYPTO;

  if (s == NULL || kek == NULL || rkey == NULL) goto done;

  s->opslimit = STORAGE_KDF_OPSLIMIT;
  s->memlimit = STORAGE_KDF_MEMLIMIT;
  randombytes_buf(s->salt, SALT_LEN);
  randombytes_buf(s->vault_key, KEY_LEN);
  randombytes_buf(rkey, KEY_LEN);

  rc = derive_master_kek(kek, master, s->salt, s->opslimit, s->memlimit);
  if (rc != STORAGE_OK) goto done;
  if ((rc = wrap_key(s->master_wrap, kek, s->vault_key)) != STORAGE_OK) goto done;
  if ((rc = wrap_key(s->recovery_wrap, rkey, s->vault_key)) != STORAGE_OK) goto done;

  vault_t empty = {0};
  if ((rc = storage_save(s, &empty)) != STORAGE_OK) goto done;

  if (sodium_bin2hex(recovery_hex, STORAGE_RECOVERY_HEX_LEN + 1, rkey, KEY_LEN) == NULL) {
    rc = STORAGE_ERR_CRYPTO;
    goto done;
  }

  *out = s;
  s = NULL;
  rc = STORAGE_OK;

done:
  if (kek) sodium_free(kek);
  if (rkey) sodium_free(rkey);
  storage_close(s);
  return rc;
}

/* mode: 0 = master password, 1 = recovery key (hex) */
static int open_common(storage_t **out, const char *path, const char *secret,
                       int mode, vault_t *vault)
{
  if (out == NULL || path == NULL || secret == NULL || vault == NULL)
    return STORAGE_ERR_ARG;
  *out = NULL;

  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int rc = read_file(path, &raw, &raw_len);
  if (rc != STORAGE_OK) return rc;

  storage_t *s = storage_new(path);
  uint8_t *kek = sodium_malloc(KEY_LEN);
  uint8_t *plain = NULL;
  if (s == NULL || kek == NULL) { rc = STORAGE_ERR_CRYPTO; goto done; }

  if ((rc = header_decode(s, raw, raw_len)) != STORAGE_OK) goto done;

  if (mode == 0) {
    if (secret[0] == '\0') { rc = STORAGE_ERR_AUTH; goto done; }
    if ((rc = derive_master_kek(kek, secret, s->salt, s->opslimit, s->memlimit)) != STORAGE_OK)
      goto done;
    if ((rc = unwrap_key(s->vault_key, s->master_wrap, kek)) != STORAGE_OK) goto done;
  } else {
    size_t bin_len = 0;
    if (sodium_hex2bin(kek, KEY_LEN, secret, strlen(secret), " -", &bin_len,
                       NULL) != 0 || bin_len != KEY_LEN) {
      rc = STORAGE_ERR_AUTH;
      goto done;
    }
    if ((rc = unwrap_key(s->vault_key, s->recovery_wrap, kek)) != STORAGE_OK) goto done;
  }

  /* Cuerpo: nonce || ciphertext */
  const uint8_t *nonce = raw + HEADER_LEN;
  const uint8_t *ct = nonce + NONCE_LEN;
  size_t ct_len = raw_len - HEADER_LEN - NONCE_LEN;
  size_t plain_len = ct_len - TAG_LEN;           /* header_decode garantiza ct_len >= TAG_LEN */

  if (plain_len == 0 || plain_len % PAD_BLOCK != 0) { rc = STORAGE_ERR_TAMPERED; goto done; }

  plain = sodium_malloc(plain_len);
  if (plain == NULL) { rc = STORAGE_ERR_CRYPTO; goto done; }

  uint8_t ad[AD_LEN];
  memcpy(ad, MAGIC, MAGIC_LEN);
  ad[MAGIC_LEN] = (uint8_t) FORMAT_VERSION;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, NULL, NULL, ct, ct_len,
                                                 ad, AD_LEN, nonce, s->vault_key) != 0) {
    rc = STORAGE_ERR_TAMPERED;
    goto done;
  }

  size_t unpadded_len;
  if (sodium_unpad(&unpadded_len, plain, plain_len, PAD_BLOCK) != 0) {
    rc = STORAGE_ERR_TAMPERED;
    goto done;
  }

  vault_t loaded = {0};
  if ((rc = deserialize_vault(plain, unpadded_len, &loaded)) != STORAGE_OK) goto done;

  *vault = loaded;
  *out = s;
  s = NULL;
  rc = STORAGE_OK;

done:
  free(raw);
  if (kek) sodium_free(kek);
  if (plain) sodium_free(plain);
  storage_close(s);
  return rc;
}

int storage_open(storage_t **out, const char *path, const char *master, vault_t *vault)
{
  return open_common(out, path, master, 0, vault);
}

int storage_open_recovery(storage_t **out, const char *path,
                          const char *recovery_hex, vault_t *vault)
{
  return open_common(out, path, recovery_hex, 1, vault);
}

int storage_change_master(storage_t *s, const char *new_master, const vault_t *vault,
                          char recovery_hex[STORAGE_RECOVERY_HEX_LEN + 1])
{
  if (s == NULL || new_master == NULL || new_master[0] == '\0' || vault == NULL ||
      recovery_hex == NULL)
    return STORAGE_ERR_ARG;

  uint8_t  old_salt[SALT_LEN], old_master[WRAP_LEN], old_recovery[WRAP_LEN];
  uint64_t old_ops = s->opslimit, old_mem = s->memlimit;
  char     hex[STORAGE_RECOVERY_HEX_LEN + 1];
  int      rc = STORAGE_ERR_CRYPTO;
  int      modified = 0;

  uint8_t *old_key = sodium_malloc(KEY_LEN);
  uint8_t *kek     = sodium_malloc(KEY_LEN);
  uint8_t *rkey    = sodium_malloc(KEY_LEN);
  if (old_key == NULL || kek == NULL || rkey == NULL) goto done;

  /* Respaldo del estado actual, para volver atrás si algo falla. */
  memcpy(old_key, s->vault_key, KEY_LEN);
  memcpy(old_salt, s->salt, SALT_LEN);
  memcpy(old_master, s->master_wrap, WRAP_LEN);
  memcpy(old_recovery, s->recovery_wrap, WRAP_LEN);
  modified = 1;

  /* Rotación completa: vault_key, recovery key y salt nuevos, costos actuales.
   * Así una copia vieja del archivo con su master (o recovery key) vieja no sirve
   * para descifrar nada de lo que se guarde desde ahora. */
  randombytes_buf(s->vault_key, KEY_LEN);
  randombytes_buf(rkey, KEY_LEN);
  randombytes_buf(s->salt, SALT_LEN);
  s->opslimit = STORAGE_KDF_OPSLIMIT;
  s->memlimit = STORAGE_KDF_MEMLIMIT;

  if ((rc = derive_master_kek(kek, new_master, s->salt, s->opslimit, s->memlimit)) != STORAGE_OK)
    goto done;
  if ((rc = wrap_key(s->master_wrap, kek, s->vault_key)) != STORAGE_OK) goto done;
  if ((rc = wrap_key(s->recovery_wrap, rkey, s->vault_key)) != STORAGE_OK) goto done;
  if (sodium_bin2hex(hex, sizeof hex, rkey, KEY_LEN) == NULL) { rc = STORAGE_ERR_CRYPTO; goto done; }

  if ((rc = storage_save(s, vault)) != STORAGE_OK) goto done;

  memcpy(recovery_hex, hex, sizeof hex);
  rc = STORAGE_OK;

done:
  if (rc != STORAGE_OK && modified) {        /* volver al estado anterior */
    memcpy(s->vault_key, old_key, KEY_LEN);
    memcpy(s->salt, old_salt, SALT_LEN);
    memcpy(s->master_wrap, old_master, WRAP_LEN);
    memcpy(s->recovery_wrap, old_recovery, WRAP_LEN);
    s->opslimit = old_ops;
    s->memlimit = old_mem;
  }
  sodium_memzero(hex, sizeof hex);
  if (old_key) sodium_free(old_key);
  if (kek) sodium_free(kek);
  if (rkey) sodium_free(rkey);
  return rc;
}