import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import os
import queue
import random
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

import nacl.bindings as nb
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from spake2 import SPAKE2_Symmetric


CHUNK_SIZE = 64 * 1024
DRAIN_EVERY = 8
MAX_FRAME = 16 * 1024 * 1024
MAX_FILE_SIZE = 100 * 1024 * 1024
OFFER_TIMEOUT = 60.0
DOWNLOAD_DIR = Path("downloads")
SEEN_IDS_MAX = 10000
HISTORY_MAX = 10000
SAVE_INTERVAL = 5.0
MSG_ACK_TIMEOUT = 30.0
DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050

T_MSG = 0x01
T_ACK = 0x02
T_PING = 0x03
T_PONG = 0x04
T_FILE_OFFER = 0x09
T_FILE_ACCEPT = 0x0A
T_FILE_DECLINE = 0x0B
T_FILE_NACK = 0x0C
T_FILE_CHUNK = 0x06
T_FILE_END = 0x07
T_FILE_ACK = 0x08

PARAGON_MAGIC = b"PARAGON\x00"
PARAGON_VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12

ARGON2_TIME = 2
ARGON2_MEMORY = 102400
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = 32


def encode_id(host, port, token):
    raw = f"{host}:{port}|{token}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_id(id_str):
    pad = "=" * (-len(id_str) % 4)
    try:
        raw = base64.urlsafe_b64decode((id_str + pad).encode("ascii"))
        hostport, token = raw.split(b"|", 1)
        host, port_s = hostport.decode("utf-8").rsplit(":", 1)
        return host, int(port_s), token.decode("utf-8")
    except Exception as e:
        raise ValueError(f"invalid Paragon ID: {e}") from e


def generate_identity(host, port):
    token = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    return encode_id(host, port, token), token


def peer_key_from_id(id_str):
    return hashlib.sha256(id_str.encode()).hexdigest()[:16]


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def seal(key, pt):
    npub = nb.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    nonce = nb.randombytes(npub)
    return nonce + nb.crypto_aead_chacha20poly1305_ietf_encrypt(pt, b"", nonce, key)


def open_(key, blob):
    npub = nb.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    return nb.crypto_aead_chacha20poly1305_ietf_decrypt(
        blob[npub:], b"", blob[:npub], key)


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def derive_session_keys(K, transcript, is_server):
    c2s = hkdf(K, b"paragon-v1", b"c2s" + transcript)
    s2c = hkdf(K, b"paragon-v1", b"s2c" + transcript)
    return (s2c, c2s) if is_server else (c2s, s2c)


def derive_key(password, salt):
    return low_level.hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt,
        time_cost=ARGON2_TIME, memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN,
        type=low_level.Type.ID)


def account_save(path, password, state):
    plaintext = json.dumps(state, ensure_ascii=False).encode("utf-8")
    compressed = gzip.compress(plaintext, compresslevel=6)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, None)
    blob = PARAGON_MAGIC + bytes([PARAGON_VERSION]) + salt + nonce + ciphertext
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_bytes(blob)
    tmp.replace(p)


def account_load(path, password):
    blob = Path(path).read_bytes()
    if len(blob) < 8 + 1 + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("account file too short")
    if not blob.startswith(PARAGON_MAGIC):
        raise ValueError("not a .paragon file (bad magic)")
    offset = len(PARAGON_MAGIC)
    version = blob[offset]
    offset += 1
    if version != PARAGON_VERSION:
        raise ValueError(f"unsupported .paragon version: {version}")
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ct = blob[offset:]
    key = derive_key(password, salt)
    try:
        compressed = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError("wrong password or corrupted file") from e
    try:
        plaintext = gzip.decompress(compressed)
    except Exception as e:
        raise ValueError(f"decompression error: {e}") from e
    return json.loads(plaintext.decode("utf-8"))


async def send_framed(w, data):
    w.write(struct.pack("!I", len(data)) + data)
    await w.drain()


async def recv_framed(r):
    hdr = await r.readexactly(4)
    n = struct.unpack("!I", hdr)[0]
    if n > MAX_FRAME:
        raise ValueError(f"frame too big: {n}")
    return await r.readexactly(n)


async def send_frame(w, tx_key, ftype, payload=b""):
    plaintext = bytes([ftype]) + payload
    enc = seal(tx_key, plaintext)
    w.write(struct.pack("!I", len(enc)) + enc)
    await w.drain()


async def recv_frame(r, rx_key):
    hdr = await r.readexactly(4)
    n = struct.unpack("!I", hdr)[0]
    if n > MAX_FRAME:
        raise ValueError(f"frame too big: {n}")
    enc = await r.readexactly(n)
    plaintext = open_(rx_key, enc)
    return plaintext[0], plaintext[1:]


def pack_msg(mid, text):
    return mid.encode() + text.encode("utf-8")


def unpack_msg(p):
    return p[:16].decode(), p[16:].decode("utf-8")


def pack_id(mid):
    return mid.encode()


def unpack_id(p):
    return p[:16].decode()


def pack_ts(ts):
    return struct.pack("!d", ts)


def unpack_ts(p):
    return struct.unpack("!d", p[:8])[0]


def pack_offer(fid, name, size, sha256_bytes):
    nb_ = name.encode("utf-8")
    if len(nb_) > 0xFFFF:
        nb_ = nb_[:0xFFFF].decode("utf-8", "ignore").encode("utf-8")
    return fid.encode() + struct.pack("!QH", size, len(nb_)) + sha256_bytes + nb_


def unpack_offer(p):
    fid = p[:16].decode()
    size, nlen = struct.unpack("!QH", p[16:26])
    sha256_bytes = p[26:58]
    name = p[58:58 + nlen].decode("utf-8")
    return fid, name, size, sha256_bytes


def pack_chunk(fid, data):
    return fid.encode() + data


def unpack_chunk(p):
    return p[:16].decode(), p[16:]


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def sanitize_filename(name):
    name = name.replace("/", "_").replace("\\", "_").replace("\x00", "")
    if name in ("", ".", "..") or name.startswith("."):
        name = "file_" + name
    return name[:200]


ONION_VERSION = b"\x03"
ONION_CHECKSUM_PREFIX = b".onion checksum"
HS_SECRET_HEADER = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
HS_PUBLIC_HEADER = b"== ed25519v1-public: type0 ==\x00\x00\x00"


def is_onion(host):
    return bool(host) and host.lower().endswith(".onion")


def onion_address_from_pubkey(pubkey):
    if len(pubkey) != 32:
        raise ValueError("ed25519 pubkey must be 32 bytes")
    checksum = hashlib.sha3_256(
        ONION_CHECKSUM_PREFIX + pubkey + ONION_VERSION).digest()[:2]
    full = pubkey + checksum + ONION_VERSION
    return base64.b32encode(full).decode("ascii").lower() + ".onion"


def generate_onion_identity():
    seed = os.urandom(32)
    pubkey, secret_key = nb.crypto_sign_seed_keypair(seed)
    onion = onion_address_from_pubkey(pubkey)
    token = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    return {
        "onion": onion,
        "seed": seed,
        "public_key": pubkey,
        "secret_key": secret_key,
        "token": token,
    }


def write_hidden_service_dir(hs_dir, onion_id, force=False):
    d = Path(hs_dir)
    d.mkdir(parents=True, exist_ok=True)
    hostname_path = d / "hostname"
    if hostname_path.exists() and not force:
        try:
            existing = hostname_path.read_text(encoding="ascii").strip()
        except Exception:
            existing = None
        if existing and existing != onion_id["onion"]:
            raise FileExistsError(
                f"HS dir {hs_dir} already holds a different onion: {existing}")
    (d / "hs_ed25519_secret_key").write_bytes(
        HS_SECRET_HEADER + onion_id["secret_key"])
    (d / "hs_ed25519_public_key").write_bytes(
        HS_PUBLIC_HEADER + onion_id["public_key"])
    hostname_path.write_bytes((onion_id["onion"] + "\n").encode("ascii"))
    try:
        os.chmod(d / "hs_ed25519_secret_key", 0o600)
        os.chmod(hostname_path, 0o644)
    except Exception:
        pass
    return str(d)


async def socks5_connect(proxy_host, proxy_port, target_host, target_port):
    r, w = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        w.write(b"\x05\x01\x00")
        await w.drain()
        resp = await r.readexactly(2)
        if resp != b"\x05\x00":
            raise RuntimeError(f"socks5: bad greeting reply {resp!r}")
        th = target_host.encode("ascii", "idna")
        if len(th) > 255:
            raise RuntimeError("socks5: hostname too long")
        req = b"\x05\x01\x00\x03" + bytes([len(th)]) + th + struct.pack("!H", target_port)
        w.write(req)
        await w.drain()
        resp = await r.readexactly(4)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise RuntimeError(f"socks5: connect failed (code {resp[1]})")
        atyp = resp[3]
        if atyp == 0x01:
            await r.readexactly(4)
        elif atyp == 0x03:
            ln = (await r.readexactly(1))[0]
            await r.readexactly(ln)
        elif atyp == 0x04:
            await r.readexactly(16)
        else:
            raise RuntimeError(f"socks5: bad atyp {atyp}")
        await r.readexactly(2)
        return r, w
    except BaseException:
        try:
            w.close()
        except Exception:
            pass
        raise


def unique_path(base, name):
    p = base / name
    if not p.exists():
        return p
    stem, ext = os.path.splitext(name)
    i = 1
    while True:
        p = base / f"{stem}.{i}{ext}"
        if not p.exists():
            return p
        i += 1


@dataclass
class Peer:
    peer_key: str
    id_str: str
    host: str
    port: int
    token_hash: str
    name: str = ""


@dataclass
class Msg:
    id: str
    peer_key: str
    body: str
    status: str = "queued"
    not_before: float = 0.0
    sent_at: float = 0.0


@dataclass
class FileTx:
    id: str
    peer_key: str
    name: str
    size: int
    path: str
    status: str = "queued"
    offset: int = 0
    not_before: float = 0.0
    offer_result: object = field(default=None, repr=False, compare=False)


@dataclass
class FileRx:
    id: str
    peer_key: str
    name: str
    size: int
    received: int = 0
    fh: object = None
    path: object = None
    hasher: object = None
    expected_sha256: bytes = b""


class Core:
    def __init__(self, account_path, password, my_identity=None,
                 delay_min=0.0, delay_max=0.0, ping_interval=30.0,
                 socks_host=DEFAULT_SOCKS_HOST, socks_port=DEFAULT_SOCKS_PORT,
                 listen_host=None, listen_port=None,
                 onion_seed=None, hs_dir=None, onion_only=False):
        self.account_path = Path(account_path)
        self._password = password
        self.delay_min = max(0.0, delay_min)
        self.delay_max = max(self.delay_min, delay_max)
        self.ping_interval = max(5.0, ping_interval)
        self.socks_host = socks_host
        self.socks_port = int(socks_port)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.hs_dir = hs_dir
        self.onion_only = bool(onion_only)
        self.onion_seed = onion_seed
        self.onion_pubkey = None

        self.my_host = None
        self.my_port = None
        self.my_token = None
        self.my_token_hash = None
        self.my_id_str = None

        self.peers = {}
        self.events = queue.Queue()
        self._queue = []
        self._file_queue = []
        self._rx_files = {}
        self._rx_offers = {}
        self._history = []
        self._seen_ids = []
        self._sessions = {}
        self._locks = {}
        self._file_sending_set = set()
        self._loop = None
        self._thread = None
        self._dirty = False

        if not self.account_path.exists():
            if my_identity is None:
                raise ValueError("my_identity required to create")
            mh, mp, mt = my_identity
            if onion_seed is not None:
                pk, _sk = nb.crypto_sign_seed_keypair(onion_seed)
                self.onion_pubkey = pk
                derived = onion_address_from_pubkey(pk)
                if mh and mh.lower() != derived.lower():
                    raise ValueError(
                        f"onion mismatch: seed -> {derived}, host -> {mh}")
                mh = derived
            if self.onion_only and not is_onion(mh):
                raise ValueError("onion-only mode requires a .onion host")
            self.my_host, self.my_port = mh, mp
            self.my_token = mt
            self.my_token_hash = sha256_hex(mt)
            self.my_id_str = encode_id(mh, mp, mt)
            self._dirty = True
            if self.onion_seed is not None and self.hs_dir:
                self._ensure_hs_dir(force=True)
        else:
            state = account_load(self.account_path, password)
            self._restore(state)

    def _restore(self, state):
        ident = state.get("identity", {})
        self.my_host = ident.get("host")
        self.my_port = ident.get("port")
        self.my_token = ident.get("token")
        self.my_token_hash = ident.get("token_hash")
        self.my_id_str = ident.get("id_str")
        seed_hex = ident.get("onion_seed")
        self.onion_seed = bytes.fromhex(seed_hex) if seed_hex else None
        if self.onion_seed is not None:
            pk, _ = nb.crypto_sign_seed_keypair(self.onion_seed)
            self.onion_pubkey = pk
            derived = onion_address_from_pubkey(pk)
            if self.my_host and self.my_host.lower() != derived.lower():
                raise ValueError(
                    f"corrupted account: onion mismatch "
                    f"({self.my_host} vs {derived})")
        if not self.my_id_str and self.my_host and self.my_port and self.my_token:
            self.my_id_str = encode_id(self.my_host, self.my_port, self.my_token)
        for pk, d in (state.get("peers") or {}).items():
            self.peers[pk] = Peer(**d)
        settings = state.get("settings", {})
        self.delay_min = settings.get("delay_min", self.delay_min)
        self.delay_max = settings.get("delay_max", self.delay_max)
        self.ping_interval = settings.get("ping_interval", self.ping_interval)
        self.socks_host = settings.get("socks_host", self.socks_host)
        self.socks_port = int(settings.get("socks_port", self.socks_port))
        self.listen_host = settings.get("listen_host", self.listen_host)
        self.listen_port = settings.get("listen_port", self.listen_port)
        self.hs_dir = settings.get("hs_dir", self.hs_dir)
        self.onion_only = bool(settings.get("onion_only", self.onion_only))
        if self.hs_dir and self.onion_seed:
            self._ensure_hs_dir()
        for d in state.get("messages", []):
            m = Msg(**d)
            if m.status == "sent":
                m.status = "queued"
            self._queue.append(m)
        for d in state.get("file_queue", []):
            f = FileTx(id=d["id"], peer_key=d.get("peer_key", ""), name=d["name"],
                       size=d["size"], path=d["path"],
                       status="queued" if d["status"] in ("offering", "sending") else d["status"],
                       offset=0, not_before=d.get("not_before", 0.0))
            self._file_queue.append(f)
        self._history = state.get("history", [])[-HISTORY_MAX:]
        self._seen_ids = state.get("seen_ids", [])[-SEEN_IDS_MAX:]

    def _serialize(self):
        return {
            "version": PARAGON_VERSION,
            "identity": {
                "host": self.my_host, "port": self.my_port,
                "token": self.my_token,
                "token_hash": self.my_token_hash,
                "id_str": self.my_id_str,
                "onion_seed": self.onion_seed.hex() if self.onion_seed else None,
            },
            "peers": {pk: asdict(p) for pk, p in self.peers.items()},
            "settings": {
                "delay_min": self.delay_min,
                "delay_max": self.delay_max,
                "ping_interval": self.ping_interval,
                "socks_host": self.socks_host,
                "socks_port": self.socks_port,
                "listen_host": self.listen_host,
                "listen_port": self.listen_port,
                "hs_dir": self.hs_dir,
                "onion_only": self.onion_only,
            },
            "messages": [asdict(m) for m in self._queue],
            "file_queue": [
                {"id": f.id, "peer_key": f.peer_key, "name": f.name,
                 "size": f.size, "path": f.path, "status": f.status,
                 "not_before": f.not_before}
                for f in self._file_queue
            ],
            "history": self._history[-HISTORY_MAX:],
            "seen_ids": self._seen_ids[-SEEN_IDS_MAX:],
        }

    def _save_sync(self):
        try:
            account_save(self.account_path, self._password, self._serialize())
            self._dirty = False
            return True
        except Exception as e:
            self._emit("save_failed", str(e))
            return False

    def start(self):
        if self._loop is not None:
            raise RuntimeError("core already started")
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="paragon-core")
        self._thread.start()

    def stop(self):
        if self._loop is None:
            return
        self._save_sync()
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        self._loop = None
        self._thread = None

    def _emit(self, *ev):
        self.events.put(ev)

    def _next_delay(self):
        if self.delay_max <= 0:
            return 0.0
        return random.uniform(self.delay_min, self.delay_max)

    def _history_append(self, peer_key, kind, text, msg_id=None):
        self._history.append({
            "peer_key": peer_key, "kind": kind, "text": text,
            "ts": time.time(), "id": msg_id or ""})
        if len(self._history) > HISTORY_MAX:
            self._history = self._history[-HISTORY_MAX:]
        self._dirty = True

    def _ensure_hs_dir(self, force=False):
        if not self.hs_dir or not self.onion_seed:
            return
        d = Path(self.hs_dir)
        required = ("hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname")
        if not force and all((d / f).exists() for f in required):
            return
        pk, sk = nb.crypto_sign_seed_keypair(self.onion_seed)
        self.onion_pubkey = pk
        write_hidden_service_dir(self.hs_dir, {
            "onion": self.my_host,
            "seed": self.onion_seed,
            "public_key": pk,
            "secret_key": sk,
        }, force=force)

    # ---------- public API ----------
    def add_peer(self, id_str, name=""):
        host, port, token = decode_id(id_str)
        if self.onion_only and not is_onion(host):
            raise ValueError(
                "onion-only mode: plain (non-.onion) addresses are not allowed")
        pk = peer_key_from_id(id_str)
        self.peers[pk] = Peer(peer_key=pk, id_str=id_str, host=host, port=port,
                              token_hash=sha256_hex(token), name=name or "")
        self._dirty = True
        self._emit("peer_added", pk)
        self._save_sync()
        return pk

    def remove_peer(self, peer_key):
        if peer_key in self.peers:
            del self.peers[peer_key]
            if self._loop:
                asyncio.run_coroutine_threadsafe(
                    self._close_session(peer_key), self._loop)
            self._dirty = True
            self._emit("peer_removed", peer_key)
            self._save_sync()

    def rename_peer(self, peer_key, name):
        if peer_key in self.peers:
            self.peers[peer_key].name = name
            self._dirty = True
            self._emit("peer_renamed", peer_key, name)
            self._save_sync()

    def set_settings(self, delay_min=None, delay_max=None, ping_interval=None):
        if delay_min is not None:
            self.delay_min = max(0.0, delay_min)
        if delay_max is not None:
            self.delay_max = max(self.delay_min, delay_max)
        if ping_interval is not None:
            self.ping_interval = max(5.0, ping_interval)
        self._dirty = True
        self._save_sync()
        self._emit("settings_changed")

    def regenerate_token(self):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._regenerate_token_async(), self._loop)

    async def _regenerate_token_async(self):
        new_token = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        self.my_token = new_token
        self.my_token_hash = sha256_hex(new_token)
        self.my_id_str = encode_id(self.my_host, self.my_port, new_token)
        self._dirty = True
        self._save_sync()
        self._emit("token_regenerated", self.my_id_str, new_token)

    def submit(self, peer_key, text):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._submit_async(peer_key, text), self._loop)

    def submit_file(self, peer_key, path):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._submit_file_async(peer_key, path), self._loop)

    def accept_file(self, fid):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._accept_file_async(fid), self._loop)

    def decline_file(self, fid):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._decline_file_async(fid), self._loop)

    def ping(self, peer_key):
        if self._loop is None:
            raise RuntimeError("core not started")
        asyncio.run_coroutine_threadsafe(self._ping_async(peer_key), self._loop)

    def get_history(self, peer_key=None):
        if peer_key is None:
            return list(self._history)
        return [h for h in self._history if h.get("peer_key") == peer_key]

    def get_message_status(self, mid):
        for m in self._queue:
            if m.id == mid:
                return m.status
        return "delivered"

    def get_peers(self):
        return list(self.peers.values())

    # ---------- internal ----------
    def _run(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        except (asyncio.CancelledError, RuntimeError):
            pass
        finally:
            self._loop.close()

    async def _main(self):
        save_task = asyncio.create_task(self._save_loop())
        try:
            await asyncio.gather(
                self._safe(self._listen_loop, "listen"),
                self._safe(self._dial_loop, "dial"),
            )
        finally:
            save_task.cancel()

    async def _safe(self, fn, name):
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._emit("save_failed", f"{name} loop crashed: {e}")

    async def _save_loop(self):
        while True:
            await asyncio.sleep(SAVE_INTERVAL)
            if self._dirty:
                self._save_sync()

    async def _accept_handshake(self, r, w):
        try:
            claimed_id_bytes = await recv_framed(r)
            claimed_id = claimed_id_bytes.decode("utf-8")
            claimed_pk = peer_key_from_id(claimed_id)
            peer = self.peers.get(claimed_pk)
            if peer is None:
                try:
                    h, p, t = decode_id(claimed_id)
                    peer = Peer(peer_key=claimed_pk, id_str=claimed_id, host=h,
                                port=p, token_hash=sha256_hex(t), name="(unknown)")
                    self.peers[claimed_pk] = peer
                    self._emit("peer_added", claimed_pk)
                    self._dirty = True
                except Exception:
                    w.close()
                    return None
            password = bytes.fromhex(peer.token_hash)
            sp = SPAKE2_Symmetric(password, idSymmetric=b"paragon")
            my_spake = sp.start()
            await send_framed(w, my_spake)
            peer_spake = await recv_framed(r)
            K = sp.finish(peer_spake)
            transcript = my_spake + peer_spake
            my_confirm = hmac.new(K, b"server-confirm" + transcript, hashlib.sha256).digest()
            await send_framed(w, my_confirm)
            peer_confirm = await recv_framed(r)
            expected = hmac.new(K, b"client-confirm" + transcript, hashlib.sha256).digest()
            if not hmac.compare_digest(peer_confirm, expected):
                w.close()
                return None
            return claimed_pk, derive_session_keys(K, transcript, is_server=True)
        except Exception:
            w.close()
            return None

    async def _dial_handshake(self, r, w, peer_key):
        peer = self.peers[peer_key]
        await send_framed(w, self.my_id_str.encode("utf-8"))
        password = bytes.fromhex(peer.token_hash)
        sp = SPAKE2_Symmetric(password, idSymmetric=b"paragon")
        my_spake = sp.start()
        await send_framed(w, my_spake)
        peer_spake = await recv_framed(r)
        K = sp.finish(peer_spake)
        transcript = peer_spake + my_spake
        peer_confirm = await recv_framed(r)
        expected = hmac.new(K, b"server-confirm" + transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(peer_confirm, expected):
            raise RuntimeError("auth failed")
        my_confirm = hmac.new(K, b"client-confirm" + transcript, hashlib.sha256).digest()
        await send_framed(w, my_confirm)
        return derive_session_keys(K, transcript, is_server=False)

    async def _run_session(self, r, w, peer_key, keys):
        if peer_key in self._sessions:
            w.close()
            return
        self._sessions[peer_key] = {"writer": w, "rx": keys[0], "tx": keys[1]}
        self._locks.setdefault(peer_key, asyncio.Lock())
        self._emit("session_up", peer_key)
        flush_task = asyncio.create_task(self._flush_loop(peer_key))
        files_task = asyncio.create_task(self._drain_files(peer_key))
        ping_task = asyncio.create_task(self._ping_loop(peer_key))
        try:
            while True:
                ftype, payload = await recv_frame(r, keys[0])
                await self._handle_frame(peer_key, ftype, payload)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError, ValueError, struct.error):
            pass
        finally:
            for t in (flush_task, files_task, ping_task):
                t.cancel()
            for t in (flush_task, files_task, ping_task):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
            self._cleanup_peer(peer_key)
            if self._sessions.get(peer_key, {}).get("writer") is w:
                del self._sessions[peer_key]
            self._dirty = True
            self._emit("session_down", peer_key)

    def _cleanup_peer(self, peer_key):
        for m in self._queue:
            if m.peer_key == peer_key and m.status == "sent":
                m.status = "queued"
        for f in self._file_queue:
            if f.peer_key == peer_key:
                if f.status in ("sending", "offering"):
                    f.status = "queued"
                    f.offset = 0
                if f.offer_result and not f.offer_result.done():
                    f.offer_result.cancel()
                f.offer_result = None
        for fid in list(self._rx_files.keys()):
            rx = self._rx_files[fid]
            if rx.peer_key == peer_key:
                if rx.fh:
                    try:
                        rx.fh.close()
                    except Exception:
                        pass
                del self._rx_files[fid]
        for fid in list(self._rx_offers.keys()):
            if self._rx_offers[fid].get("peer_key") == peer_key:
                del self._rx_offers[fid]

    async def _close_session(self, peer_key):
        s = self._sessions.get(peer_key)
        if s:
            try:
                s["writer"].close()
            except Exception:
                pass

    async def _handle_frame(self, peer_key, ftype, payload):
        session = self._sessions.get(peer_key)
        if not session:
            return
        w, tx = session["writer"], session["tx"]

        if ftype == T_MSG:
            mid, text = unpack_msg(payload)
            if mid not in self._seen_ids:
                self._seen_ids.append(mid)
                if len(self._seen_ids) > SEEN_IDS_MAX:
                    self._seen_ids = self._seen_ids[-SEEN_IDS_MAX:]
                self._history_append(peer_key, "in", text, mid)
                self._emit("peer_msg", peer_key, text)
            await send_frame(w, tx, T_ACK, pack_id(mid))
        elif ftype == T_ACK:
            mid = unpack_id(payload)
            for m in self._queue:
                if m.id == mid and m.peer_key == peer_key and m.status != "delivered":
                    m.status = "delivered"
                    self._dirty = True
                    self._emit("msg_delivered", peer_key, m.id)
                    break
        elif ftype == T_PING:
            await send_frame(w, tx, T_PONG, payload)
        elif ftype == T_PONG:
            rtt = (time.monotonic() - unpack_ts(payload)) * 1000
            self._emit("pong", peer_key, rtt)
        elif ftype == T_FILE_OFFER:
            fid, name, size, sha256_bytes = unpack_offer(payload)
            safe = sanitize_filename(name)
            if fid in self._rx_offers or fid in self._rx_files:
                return
            if size > MAX_FILE_SIZE:
                await send_frame(w, tx, T_FILE_DECLINE, pack_id(fid))
                return
            self._rx_offers[fid] = {"peer_key": peer_key, "name": safe,
                                    "size": size, "sha256": sha256_bytes}
            self._emit("file_offer", peer_key, fid, safe, size)
        elif ftype == T_FILE_ACCEPT:
            fid = unpack_id(payload)
            for f in self._file_queue:
                if f.id == fid and f.peer_key == peer_key and f.offer_result and not f.offer_result.done():
                    f.offer_result.set_result("accepted")
                    break
        elif ftype == T_FILE_DECLINE:
            fid = unpack_id(payload)
            for f in self._file_queue:
                if f.id == fid and f.peer_key == peer_key and f.offer_result and not f.offer_result.done():
                    f.offer_result.set_result("declined")
                    break
        elif ftype == T_FILE_CHUNK:
            fid, chunk = unpack_chunk(payload)
            rx = self._rx_files.get(fid)
            if not rx or rx.peer_key != peer_key:
                return
            if rx.received + len(chunk) > rx.size:
                try:
                    rx.fh.close()
                except Exception:
                    pass
                del self._rx_files[fid]
                try:
                    if rx.path:
                        rx.path.unlink()
                except Exception:
                    pass
                self._emit("file_failed", peer_key, fid,
                           "received more data than declared size")
                await send_frame(w, tx, T_FILE_NACK, pack_id(fid))
                return
            try:
                rx.fh.write(chunk)
                rx.hasher.update(chunk)
                rx.received += len(chunk)
                self._emit("file_progress", peer_key, fid, "in", rx.received, rx.size)
            except Exception as e:
                try:
                    rx.fh.close()
                except Exception:
                    pass
                del self._rx_files[fid]
                try:
                    if rx.path:
                        rx.path.unlink()
                except Exception:
                    pass
                self._emit("file_failed", peer_key, fid, str(e))
                await send_frame(w, tx, T_FILE_NACK, pack_id(fid))
        elif ftype == T_FILE_END:
            fid = unpack_id(payload)
            rx = self._rx_files.pop(fid, None)
            if not rx or rx.peer_key != peer_key:
                await send_frame(w, tx, T_FILE_NACK, pack_id(fid))
                return
            rx.fh.close()
            actual = rx.hasher.digest()
            if not hmac.compare_digest(actual, rx.expected_sha256):
                try:
                    rx.path.unlink()
                except Exception:
                    pass
                self._emit("file_failed", peer_key, fid, "integrity check failed")
                await send_frame(w, tx, T_FILE_NACK, pack_id(fid))
                return
            self._emit("file_done", peer_key, fid, "in", str(rx.path))
            await send_frame(w, tx, T_FILE_ACK, pack_id(fid))
        elif ftype == T_FILE_NACK:
            fid = unpack_id(payload)
            for f in self._file_queue:
                if f.id == fid and f.peer_key == peer_key:
                    f.status = "failed"
                    self._dirty = True
                    self._emit("file_failed", peer_key, fid, "rejected by peer")
                    break
        elif ftype == T_FILE_ACK:
            fid = unpack_id(payload)
            for f in self._file_queue:
                if f.id == fid and f.peer_key == peer_key:
                    f.status = "sent"
                    self._dirty = True
                    self._emit("file_done", peer_key, fid, "out", None)
                    break

    async def _flush_loop(self, peer_key):
        while peer_key in self._sessions:
            session = self._sessions.get(peer_key)
            if not session:
                return
            w, tx = session["writer"], session["tx"]
            now = time.monotonic()
            sent_any = False
            for m in self._queue:
                if m.peer_key != peer_key:
                    continue
                if m.status == "sent" and m.sent_at and (now - m.sent_at) > MSG_ACK_TIMEOUT:
                    m.status = "queued"
                    self._dirty = True
                if m.status != "queued" or m.not_before > now:
                    continue
                try:
                    await send_frame(w, tx, T_MSG, pack_msg(m.id, m.body))
                    m.status = "sent"
                    m.sent_at = now
                    self._dirty = True
                    sent_any = True
                except Exception:
                    return
            await asyncio.sleep(0.3 if sent_any else 0.5)

    async def _ping_loop(self, peer_key):
        while peer_key in self._sessions:
            await asyncio.sleep(self.ping_interval)
            session = self._sessions.get(peer_key)
            if not session:
                return
            try:
                await send_frame(session["writer"], session["tx"],
                                 T_PING, pack_ts(time.monotonic()))
            except Exception:
                return

    async def _drain_files(self, peer_key):
        if peer_key in self._file_sending_set:
            return
        self._file_sending_set.add(peer_key)
        try:
            while peer_key in self._sessions:
                now = time.monotonic()
                ready = [f for f in self._file_queue
                         if f.peer_key == peer_key and f.status == "queued"
                         and f.not_before <= now]
                if not ready:
                    await asyncio.sleep(0.5)
                    continue
                f = ready[0]
                try:
                    await self._send_one_file(peer_key, f)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    f.status = "failed"
                    self._dirty = True
                    self._emit("file_failed", peer_key, f.id, str(e))
        finally:
            self._file_sending_set.discard(peer_key)

    def _hash_file(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.digest()

    async def _send_one_file(self, peer_key, f):
        session = self._sessions.get(peer_key)
        if not session:
            return
        w, tx = session["writer"], session["tx"]
        f.status = "offering"
        f.offset = 0
        size = os.path.getsize(f.path)
        if size != f.size:
            f.size = size
        self._emit("file_hashing", peer_key, f.id)
        sha = await asyncio.get_running_loop().run_in_executor(None, self._hash_file, f.path)
        f.offer_result = asyncio.get_running_loop().create_future()
        fid_bytes = f.id.encode()
        plaintext = bytes([T_FILE_OFFER]) + pack_offer(f.id, f.name, f.size, sha)
        enc = seal(tx, plaintext)
        w.write(struct.pack("!I", len(enc)) + enc)
        await w.drain()
        self._emit("file_offered", peer_key, f.id)
        try:
            done, _ = await asyncio.wait([f.offer_result], timeout=OFFER_TIMEOUT)
        except asyncio.CancelledError:
            raise
        if not done:
            f.status = "failed"
            self._dirty = True
            self._emit("file_failed", peer_key, f.id, "offer timeout")
            return
        try:
            result = f.offer_result.result()
        except asyncio.CancelledError:
            f.status = "queued"
            return
        if result != "accepted":
            f.status = "declined" if result == "declined" else "failed"
            self._dirty = True
            if result == "declined":
                self._emit("file_declined", peer_key, f.id)
            else:
                self._emit("file_failed", peer_key, f.id, result)
            return
        f.status = "sending"
        count = 0
        with open(f.path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                plaintext = bytes([T_FILE_CHUNK]) + fid_bytes + chunk
                enc = seal(tx, plaintext)
                w.write(struct.pack("!I", len(enc)) + enc)
                f.offset += len(chunk)
                count += 1
                if count % DRAIN_EVERY == 0:
                    await w.drain()
                    self._emit("file_progress", peer_key, f.id, "out", f.offset, f.size)
            await w.drain()
        self._emit("file_progress", peer_key, f.id, "out", f.offset, f.size)
        plaintext = bytes([T_FILE_END]) + fid_bytes
        enc = seal(tx, plaintext)
        w.write(struct.pack("!I", len(enc)) + enc)
        await w.drain()

    async def _listen_loop(self):
        async def on_accept(r, w):
            result = await self._accept_handshake(r, w)
            if result:
                peer_key, keys = result
                await self._run_session(r, w, peer_key, keys)
        if is_onion(self.my_host):
            bind_host = self.listen_host or "127.0.0.1"
            bind_port = self.listen_port or self.my_port
        else:
            bind_host, bind_port = self.my_host, self.my_port
        srv = await asyncio.start_server(on_accept, bind_host, bind_port)
        async with srv:
            await srv.serve_forever()

    async def _dial_loop(self):
        while True:
            for pk in list(self.peers.keys()):
                if pk in self._sessions:
                    continue
                if not self._peer_has_queued_work(pk):
                    continue
                peer = self.peers.get(pk)
                if not peer:
                    continue
                if self.onion_only and not is_onion(peer.host):
                    continue
                try:
                    if is_onion(peer.host):
                        r, w = await asyncio.wait_for(
                            socks5_connect(self.socks_host, self.socks_port,
                                           peer.host, peer.port), timeout=30)
                    else:
                        r, w = await asyncio.wait_for(
                            asyncio.open_connection(peer.host, peer.port), timeout=10)
                    keys = await self._dial_handshake(r, w, pk)
                    if keys:
                        asyncio.create_task(self._run_session(r, w, pk, keys))
                except Exception:
                    pass
            await asyncio.sleep(1.5)

    def _peer_has_queued_work(self, peer_key):
        now = time.monotonic()
        if any(m.peer_key == peer_key and m.status == "queued" and m.not_before <= now
               for m in self._queue):
            return True
        return any(f.peer_key == peer_key and f.status == "queued" and f.not_before <= now
                   for f in self._file_queue)

    async def _submit_async(self, peer_key, text):
        m = Msg(id=uuid.uuid4().hex[:16], peer_key=peer_key, body=text,
                not_before=time.monotonic() + self._next_delay())
        self._queue.append(m)
        self._history_append(peer_key, "out", text, m.id)
        self._dirty = True
        self._emit("msg_queued", peer_key, m.id, text)

    async def _submit_file_async(self, peer_key, path):
        if not os.path.isfile(path):
            self._emit("file_failed", peer_key, "", "not a file")
            return
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            self._emit("file_failed", peer_key, "",
                       f"too large ({fmt_size(size)} > {fmt_size(MAX_FILE_SIZE)})")
            return
        name = os.path.basename(path)
        f = FileTx(id=uuid.uuid4().hex[:16], peer_key=peer_key, name=name,
                   size=size, path=path, not_before=time.monotonic() + self._next_delay())
        self._file_queue.append(f)
        self._dirty = True
        self._emit("file_queued", peer_key, f.id, name, size)

    async def _accept_file_async(self, fid):
        offer = self._rx_offers.pop(fid, None)
        if not offer:
            return
        peer_key = offer["peer_key"]
        session = self._sessions.get(peer_key)
        if not session:
            self._emit("file_failed", peer_key, fid, "no session")
            return
        DOWNLOAD_DIR.mkdir(exist_ok=True)
        safe = sanitize_filename(offer["name"])
        path = unique_path(DOWNLOAD_DIR, safe)
        try:
            fh = open(path, "wb")
        except Exception as e:
            self._emit("file_failed", peer_key, fid, f"open failed: {e}")
            try:
                await send_frame(session["writer"], session["tx"],
                                 T_FILE_DECLINE, pack_id(fid))
            except Exception:
                pass
            return
        rx = FileRx(id=fid, peer_key=peer_key, name=safe, size=offer["size"],
                    fh=fh, path=path, hasher=hashlib.sha256(),
                    expected_sha256=offer["sha256"])
        self._rx_files[fid] = rx
        self._emit("file_in_start", peer_key, fid, safe, offer["size"])
        await send_frame(session["writer"], session["tx"], T_FILE_ACCEPT, pack_id(fid))

    async def _decline_file_async(self, fid):
        offer = self._rx_offers.pop(fid, None)
        if not offer:
            return
        peer_key = offer["peer_key"]
        session = self._sessions.get(peer_key)
        if session:
            try:
                await send_frame(session["writer"], session["tx"],
                                 T_FILE_DECLINE, pack_id(fid))
            except Exception:
                pass

    async def _ping_async(self, peer_key):
        session = self._sessions.get(peer_key)
        if not session:
            self._emit("ping_unavailable", peer_key)
            return
        try:
            await send_frame(session["writer"], session["tx"],
                             T_PING, pack_ts(time.monotonic()))
        except Exception:
            self._emit("ping_unavailable", peer_key)