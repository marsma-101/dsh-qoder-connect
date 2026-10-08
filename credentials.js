// credentials.js — Qoder CN desktop credential decryption for dsh-qoder-connect.
//
// The Qoder CN desktop app stores its sign-in in
// `<APPDATA>\com.qodercn.app.<channel>\auth.v1.dat` (channel = stable / beta /
// dev …) using the Chromium OSCrypt scheme: the AES-256-GCM key lives in the
// same directory's `Local State` → os_crypt.encrypted_key (DPAPI-protected,
// "DPAPI" prefix), and the blob itself is
// "v10" + 12-byte nonce + ciphertext + 16-byte auth tag.
//
// Decrypted payload: { schemaVersion, token (dt-…), refreshToken (drt-…),
// expiresAt, refreshTokenExpiresAt, user { id, name, … } }.
//
// Discovery: every `com.qodercn.app.*` directory under %APPDATA% is scanned;
// each candidate is decrypted with its own per-variant cached OSCrypt key and
// the first candidate yielding a valid dt- token wins (stable channel first,
// then newest directory mtime). An explicit directory (Config card `dataDir`
// or the QODER_DATA_DIR environment variable — either the data folder or the
// auth.v1.dat file itself) always wins over the scan.
//
// Key cache: one file per variant at `<keyDir>\oscrypt-<channel>.key` because
// each variant directory carries its own DPAPI-wrapped key. The pre-existing
// legacy `oscrypt.key` is treated as the stable variant's cache: when
// `oscrypt-stable.key` is missing, it is copied over (original left in place).
//
// Token lifecycle: the desktop app refreshes its own token in place; we
// re-read the file whenever its mtime changes, so a desktop-side refresh is
// followed automatically.

import { createDecipheriv } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, utimesSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const APP_PREFIX = "com.qodercn.app.";
const DEFAULT_CHANNEL = "stable";
const AUTH_FILE = "auth.v1.dat";

/** User-facing hint appended when no candidate credential can be decrypted. */
export const SIGN_IN_HINT =
	"请确认 Qoder 桌面程序已启动并登录过（扫描模型列表与路径期间需保持程序处于启动状态）；首次使用请先在 Qoder 里完成一次登录";

/** Enumerate candidate Qoder data directories under %APPDATA% (stable first, then newest mtime). */
export function listQoderDataDirs(root = process.env.APPDATA ?? "") {
	if (root === "") return [];
	let entries;
	try {
		entries = readdirSync(root, { withFileTypes: true });
	} catch {
		return [];
	}
	const out = [];
	for (const entry of entries) {
		if (!entry.isDirectory() || !entry.name.startsWith(APP_PREFIX)) continue;
		const dir = join(root, entry.name);
		let mtimeMs = 0;
		try { mtimeMs = statSync(dir).mtimeMs; } catch {}
		out.push({ name: entry.name, dir, mtimeMs });
	}
	out.sort((a, b) => {
		const aStable = a.name === `${APP_PREFIX}${DEFAULT_CHANNEL}` ? 0 : 1;
		const bStable = b.name === `${APP_PREFIX}${DEFAULT_CHANNEL}` ? 0 : 1;
		if (aStable !== bStable) return aStable - bStable;
		return b.mtimeMs - a.mtimeMs;
	});
	return out;
}

/** Per-variant key-cache filename slug (safe for filenames; non-empty). */
function variantSlug(dirName) {
	const suffix = dirName.startsWith(APP_PREFIX) ? dirName.slice(APP_PREFIX.length) : dirName;
	const slug = suffix.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
	return slug === "" ? "custom" : slug;
}

/**
 * Key-cache path for one variant. Legacy compatibility: the pre-discovery
 * build cached the stable variant's key at `oscrypt.key`; when the specific
 * `oscrypt-stable.key` is missing, the legacy file is copied over (the
 * original file is kept untouched).
 */
function keyPathFor(keyDir, slug) {
	const specific = join(keyDir, `oscrypt-${slug}.key`);
	if (slug === DEFAULT_CHANNEL && !existsSync(specific)) {
		const legacy = join(keyDir, "oscrypt.key");
		if (existsSync(legacy)) {
			try {
				copyFileSync(legacy, specific);
				// Refresh atime/mtime on the legacy file so its age stays a
				// truthful signal that stable is actively in use.
				try {
					const now = new Date();
					utimesSync(legacy, now, now);
				} catch {}
			} catch {}
		}
	}
	return specific;
}

/** Normalize an explicit dataDir setting: accepts the data folder or the auth.v1.dat path itself. */
function normalizeExplicitDir(raw) {
	const value = String(raw ?? "").trim();
	if (value === "") return undefined;
	const trimmed = value.replace(/[\\/]+$/, "");
	const dir = basename(trimmed) === AUTH_FILE ? dirname(trimmed) : trimmed;
	return existsSync(join(dir, AUTH_FILE)) ? dir : undefined;
}

/** Ensure the decrypted OSCrypt AES key for dataDir exists at keyPath (PowerShell DPAPI once). */
export async function ensureOsCryptKey(dataDir, keyPath) {
	if (existsSync(keyPath)) return true;
	if (!existsSync(join(dataDir, "Local State")) || !existsSync(join(dataDir, AUTH_FILE))) return false;
	mkdirSync(dirname(keyPath), { recursive: true });
	const ps = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$ls = Get-Content '${join(dataDir, "Local State")}' -Raw | ConvertFrom-Json
$blob = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
if ($blob[0] -eq 0x44) { $blob = $blob[5..($blob.Length-1)] }
$key = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes('${keyPath}', $key)
`;
	await execFileAsync("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], { timeout: 30_000 });
	return existsSync(keyPath);
}

/** Read + decrypt one variant's auth.v1.dat with the cached key; returns the auth object or undefined. */
export function readAuthFrom(dataDir, keyPath) {
	const authFile = join(dataDir, AUTH_FILE);
	if (!existsSync(authFile) || !existsSync(keyPath)) return undefined;
	try {
		const aesKey = readFileSync(keyPath);
		const enc = readFileSync(authFile);
		const prefix = enc.subarray(0, 3).toString("ascii");
		if (prefix !== "v10") throw new Error(`unexpected prefix ${prefix}`);
		const body = enc.subarray(3);
		const nonce = body.subarray(0, 12);
		const tag = body.subarray(body.length - 16);
		const cipher = body.subarray(12, body.length - 16);
		const decipher = createDecipheriv("aes-256-gcm", aesKey, nonce);
		decipher.setAuthTag(tag);
		const plain = Buffer.concat([decipher.update(cipher), decipher.final()]);
		const auth = JSON.parse(plain.toString("utf8"));
		if (typeof auth?.token !== "string" || auth.token.length === 0) return undefined;
		return auth;
	} catch {
		return undefined;
	}
}

function isDtToken(auth) {
	return typeof auth?.token === "string" && auth.token.startsWith("dt-");
}

/** Try one candidate: ensure its per-variant key, decrypt, retry once with a re-exported key on failure. */
async function attemptCandidate(candidate, keyDir, logger) {
	const slug = variantSlug(candidate.name);
	const keyPath = keyPathFor(keyDir, slug);
	let auth = undefined;
	if (await ensureOsCryptKey(candidate.dir, keyPath)) {
		auth = readAuthFrom(candidate.dir, keyPath);
		if (auth === undefined && existsSync(keyPath)) {
			// Cached key may be stale (app re-encrypted, cache copied from
			// another machine); drop it and re-export via DPAPI once.
			try { rmSync(keyPath, { force: true }); } catch {}
			if (await ensureOsCryptKey(candidate.dir, keyPath)) auth = readAuthFrom(candidate.dir, keyPath);
		}
	}
	if (auth !== undefined && typeof logger?.info === "function") {
		logger.info(`dsh-qoder-connect: ${candidate.name}: credential readable${isDtToken(auth) ? "" : " (token lacks dt- prefix)"}`);
	}
	return { candidate, slug, keyPath, auth };
}

export class QoderCredentialStore {
	constructor(options = {}) {
		this.logger = options.logger;
		const keyDir = options.keyDir ?? (options.keyPath !== undefined ? dirname(options.keyPath) : undefined);
		if (keyDir === undefined || keyDir === "") {
			throw new Error("qoder-connect: QoderCredentialStore requires keyDir (or a legacy keyPath to derive it from)");
		}
		this.keyDir = keyDir;
		// Explicit data dir override: string or () => string (Config card
		// `dataDir` / QODER_DATA_DIR). Wins over scanning whenever set.
		this.dataDir = options.dataDir;
		this.active = undefined; // { name, dir, slug, keyPath }
		this.current = undefined;
		this.lastMtimeMs = 0;
	}

	explicitDir() {
		const raw = typeof this.dataDir === "function" ? this.dataDir() : this.dataDir;
		return normalizeExplicitDir(raw);
	}

	/** Load/refresh the credential; re-reads when the desktop file changes. */
	async resolve() {
		const explicit = this.explicitDir();
		// Fast path: re-read the previously adopted variant (same cost as the
		// old single-dir flow); full rescan only when it stops decrypting.
		// A set explicit dir always takes the explicit path below instead.
		if (explicit === undefined && this.active !== undefined) {
			const auth = readAuthFrom(this.active.dir, this.active.keyPath);
			if (auth !== undefined) {
				this.adopt(this.active, auth);
				return this.current;
			}
			this.logger?.info?.(`dsh-qoder-connect: ${this.active.name} credential no longer readable; rescanning`);
			this.active = undefined;
		}
		let picked = undefined;
		let scannedNames = [];
		if (explicit !== undefined) {
			const name = basename(explicit);
			picked = await attemptCandidate({ name, dir: explicit, mtimeMs: 0 }, this.keyDir, this.logger);
			if (picked.auth === undefined) {
				this.logger?.info?.(`dsh-qoder-connect: explicit dataDir ${explicit} unreadable; falling back to scan`);
				picked = undefined;
			}
		}
		if (picked === undefined) {
			const candidates = listQoderDataDirs();
			scannedNames = candidates.map((c) => c.name);
			if (candidates.length > 0) {
				this.logger?.info?.(`dsh-qoder-connect: scanning ${candidates.length} Qoder data dir(s): ${scannedNames.join(", ")}`);
			}
			const results = [];
			for (const candidate of candidates) {
				results.push(await attemptCandidate(candidate, this.keyDir, this.logger));
			}
			// Candidates arrive stable-first / newest-mtime-first; prefer the
			// first valid dt- token, fall back to any readable credential.
			picked = results.find((r) => isDtToken(r.auth)) ?? results.find((r) => r.auth !== undefined);
		}
		if (picked === undefined || picked.auth === undefined) {
			const where = scannedNames.length > 0
				? ` (scanned: ${scannedNames.join(", ")})`
				: " (no com.qodercn.app.* data directory found under %APPDATA%)";
			throw new Error(`qoder-connect: no readable Qoder credential found${where}. ${SIGN_IN_HINT}`);
		}
		this.active = { name: picked.candidate.name, dir: picked.candidate.dir, slug: picked.slug, keyPath: picked.keyPath };
		this.logger?.info?.(`dsh-qoder-connect: using Qoder data dir ${this.active.name} (key cache oscrypt-${this.active.slug}.key)`);
		this.adopt(this.active, picked.auth);
		return this.current;
	}

	adopt(active, auth) {
		let mtime = 0;
		try { mtime = statSync(join(active.dir, AUTH_FILE)).mtimeMs; } catch {}
		if (this.current === undefined || auth.token !== this.current.token || mtime !== this.lastMtimeMs) {
			if (this.current !== undefined) this.logger?.info?.("dsh-qoder-connect: desktop credential changed; re-adopted");
			this.current = auth;
			this.lastMtimeMs = mtime;
		}
	}

	/** Card status summary; never throws. */
	async status() {
		try {
			const auth = await this.resolve();
			const expiry = Date.parse(auth.expiresAt ?? "");
			return {
				state: "signed-in",
				userId: auth.user?.id ?? "",
				name: auth.user?.name ?? "",
				...(this.active !== undefined ? { dataDir: this.active.name } : {}),
				...(Number.isFinite(expiry) ? { expiresAt: expiry } : {}),
			};
		} catch (error) {
			return { state: "signed-out", reason: String(error?.message ?? error).slice(0, 300) };
		}
	}
}
