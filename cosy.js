// cosy.js — Qoder COSY request signing for dsh-qoder-connect.
//
// Ported from qoder2api (MIT) internal/cosy: device fingerprint derivation,
// session establishment (RSA temp key + AES-CBC auth payload), request
// signing, and the custom-alphabet payload encoder.

import { createHash, createCipheriv, publicEncrypt, randomBytes, constants } from "node:crypto";

export const VERSION = "1.0.10";
export const APP_CODE = "cosy";
const SECRET_B64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="; // base64("war, war never changes")
const SEP = "&";
const SERVER_PUB_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`;

export function md5Hex(s) {
	return createHash("md5").update(s).digest("hex");
}

function saltedSeed(seed, installSalt) {
	return installSalt ? `${seed}|salt:${installSalt}` : seed;
}

function deriveID(seed, salt, installSalt) {
	return md5Hex(`${salt}:${saltedSeed(seed, installSalt)}`);
}

export function deriveMachineID(seed, installSalt = "") {
	return deriveID(seed, "machine", installSalt);
}

export function deriveMachineType(seed, installSalt = "") {
	return deriveID(seed, "machinetype", installSalt).slice(0, 18);
}

export function deriveMachineToken(seed, installSalt = "") {
	const sum = createHash("sha512").update(`machinetoken:${saltedSeed(seed, installSalt)}`).digest();
	return sum.toString("base64url").slice(0, 43);
}

export function fingerprintSeed(uid, credential) {
	return uid !== "" ? uid : `cred:${credential}`;
}

export function currentDate() {
	return new Date().toUTCString().replace("GMT", "GMT");
}

export function signLegacy(date) {
	return md5Hex(APP_CODE + SEP + SECRET_B64 + SEP + date);
}

function aesCbcEncrypt(plain, key) {
	// PKCS7 pad, IV = first 16 bytes of key (matches Go implementation).
	const bs = 16;
	const pad = bs - (plain.length % bs);
	const padded = Buffer.concat([plain, Buffer.alloc(pad, pad)]);
	const iv = key.subarray(0, bs);
	const cipher = createCipheriv("aes-128-cbc", key, iv);
	cipher.setAutoPadding(false);
	return Buffer.concat([cipher.update(padded), cipher.final()]);
}

export function newUUID() {
	const b = randomBytes(16);
	const hex = b.toString("hex");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function authPayloadJSON(id) {
	return JSON.stringify({
		name: id.name ?? "",
		aid: id.aid ?? "",
		uid: id.uid ?? "",
		yx_uid: id.yxUid ?? "",
		organization_id: id.organizationId ?? "",
		organization_name: id.organizationName ?? "",
		user_type: id.userType ?? "",
		security_oauth_token: id.securityOauthToken ?? "",
		refresh_token: id.refreshToken ?? "",
	});
}

/** Build a COSY session context from an AuthIdentity + derived fingerprints. */
export function newSession(identity, machineId, machineToken, machineType) {
	const tempKey = randomBytes(8).toString("hex"); // 16 chars
	const cosyKeyBytes = publicEncrypt(
		{ key: SERVER_PUB_KEY, padding: constants.RSA_PKCS1_PADDING },
		Buffer.from(tempKey, "utf8"),
	);
	const cosyKey = cosyKeyBytes.toString("base64");
	const info = aesCbcEncrypt(Buffer.from(authPayloadJSON(identity), "utf8"), Buffer.from(tempKey, "utf8")).toString("base64");
	return { identity, machineId, machineToken, machineType, tempKey, cosyKey, info };
}

export function buildPayloadB64(info) {
	const m = {
		cosyVersion: VERSION,
		ideVersion: "",
		info,
		requestId: newUUID(),
		version: "v1",
	};
	return Buffer.from(JSON.stringify(m), "utf8").toString("base64");
}

export function signRequest(payloadB64, cosyKey, cosyDate, body, pathSig) {
	return md5Hex(`${payloadB64}\n${cosyKey}\n${cosyDate}\n${body}\n${pathSig}`);
}

export function composeBearer(payloadB64, sig) {
	return `Bearer COSY.${payloadB64}.${sig}`;
}

export function pathSigFrom(rawURL) {
	const u = new URL(rawURL);
	let p = u.pathname;
	if (p.startsWith("/algo")) p = p.slice(5);
	return p;
}

// ---- custom-alphabet payload encoder (bridge/internal/cosy/encoding.go) ----
const CUSTOM_ALPHABET = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function encode(plaintext) {
	// Standard base64 with '=' padding → custom '$' pad (encoding.go: s2c['='] = '$').
	const std0 = Buffer.from(plaintext).toString("base64");
	const n0 = std0.length;
	const a0 = Math.floor(n0 / 3);
	// Rearrangement operates on the PADDED string first (Go: std includes '=').
	const rearranged0 = std0.slice(n0 - a0) + std0.slice(a0, n0 - a0) + std0.slice(0, a0);
	// Now map every char: '=' → '$', others via std→custom table.
	let out = "";
	for (let i = 0; i < n0; i++) {
		const ch = rearranged0[i];
		if (ch === "=") { out += "$"; continue; }
		const idx = STD_ALPHABET.indexOf(ch);
		if (idx < 0) throw new Error(`char out of alphabet: ${ch}`);
		out += CUSTOM_ALPHABET[idx];
	}
	return out;
}

/** Sign + encode headers for one request (mirrors BearerClient.buildHeaders). */
export function buildHeaders(sess, fullURL, bodyStr, accept) {
	const payloadB64 = buildPayloadB64(sess.info);
	const date = String(Math.floor(Date.now() / 1000));
	const sig = signRequest(payloadB64, sess.cosyKey, date, bodyStr, pathSigFrom(fullURL));
	return {
		"cosy-data-policy": "agree",
		"content-type": "application/json",
		"cosy-machinetype": sess.machineType,
		"cosy-clienttype": "5",
		"cosy-date": date,
		"cosy-user": sess.identity.uid,
		"cosy-key": sess.cosyKey,
		"cache-control": "no-cache",
		accept,
		authorization: composeBearer(payloadB64, sig),
		"cosy-version": VERSION,
		"cosy-machineid": sess.machineId,
		"cosy-machinetoken": sess.machineToken,
		"login-version": "v2",
		"user-agent": "Go-http-client/2.0",
		"cosy-scene": "assistant",
		"cosy-business-product": "ide",
		"cosy-business-type": "agent",
	};
}
