// credentials.js — Qoder CN desktop credential decryption for dsh-qoder-connect.
//
// The Qoder CN desktop app stores its sign-in in
// `<APPDATA>\com.qodercn.app.stable\auth.v1.dat` using the Chromium OSCrypt
// scheme: the AES-256-GCM key lives in `Local State` → os_crypt.encrypted_key
// (DPAPI-protected, "DPAPI" prefix), and the blob itself is
// "v10" + 12-byte nonce + ciphertext + 16-byte auth tag.
//
// Decrypted payload: { schemaVersion, token (dt-…), refreshToken (drt-…),
// expiresAt, refreshTokenExpiresAt, user { id, name, … } }.
//
// Token lifecycle: the desktop app refreshes its own token in place; we
// re-read the file whenever its mtime changes, so a desktop-side refresh is
// followed automatically.

import { createDecipheriv } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const APP_DIR = "com.qodercn.app.stable";

function appDir() {
	return `${process.env.APPDATA ?? ""}\\${APP_DIR}`;
}

function authPath() {
	return `${appDir()}\\auth.v1.dat`;
}

/** Ensure the decrypted OSCrypt AES key exists at keyPath (PowerShell DPAPI once). */
export async function ensureOsCryptKey(keyPath) {
	if (existsSync(keyPath)) return true;
	if (!existsSync(`${appDir()}\\Local State`) || !existsSync(authPath())) return false;
	const { mkdirSync } = await import("node:fs");
	mkdirSync(keyPath.slice(0, keyPath.lastIndexOf("\\")), { recursive: true });
	const ps = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$ls = Get-Content '${appDir()}\\Local State' -Raw | ConvertFrom-Json
$blob = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
if ($blob[0] -eq 0x44) { $blob = $blob[5..($blob.Length-1)] }
$key = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes('${keyPath}', $key)
`;
	await execFileAsync("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], { timeout: 30_000 });
	return existsSync(keyPath);
}

/** Read + decrypt auth.v1.dat; returns the auth object or undefined. */
function readDesktopAuth(keyPath) {
	if (!existsSync(authPath()) || !existsSync(keyPath)) return undefined;
	try {
		const aesKey = readFileSync(keyPath);
		const enc = readFileSync(authPath());
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

export class QoderCredentialStore {
	constructor(options = {}) {
		this.keyPath = options.keyPath;
		this.logger = options.logger;
		this.current = undefined;
		this.lastMtimeMs = 0;
	}

	/** Load/refresh the credential; re-reads when the desktop file changes. */
	async resolve() {
		await ensureOsCryptKey(this.keyPath);
		const auth = readDesktopAuth(this.keyPath);
		if (auth === undefined) {
			throw new Error("qoder-connect: Qoder CN is not signed in on this machine (auth.v1.dat unreadable)");
		}
		let mtime = 0;
		try { mtime = statSync(authPath()).mtimeMs; } catch {}
		if (this.current === undefined || auth.token !== this.current.token || mtime !== this.lastMtimeMs) {
			if (this.current !== undefined) this.logger?.info?.("dsh-qoder-connect: desktop credential changed; re-adopted");
			this.current = auth;
			this.lastMtimeMs = mtime;
		}
		return this.current;
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
				...(Number.isFinite(expiry) ? { expiresAt: expiry } : {}),
			};
		} catch (error) {
			return { state: "signed-out", reason: String(error?.message ?? error).slice(0, 300) };
		}
	}
}
