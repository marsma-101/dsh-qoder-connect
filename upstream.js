// upstream.js — Qoder CN upstream client for dsh-qoder-connect.
//
// Endpoints and protocol ported from qoder2api (MIT): userinfo, model list,
// and the agent_chat_generation SSE stream over gateway.qoder.com.cn with
// the COSY signature scheme. The chat body is the extracted baseprompt.json
// template with {UUID…}/{TIME1} placeholders and our messages injected.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
	buildHeaders, deriveMachineID, deriveMachineToken, deriveMachineType,
	encode, fingerprintSeed, newSession, newUUID,
} from "./cosy.js";

const CN = {
	Userinfo: "https://openapi.qoder.com.cn/api/v1/userinfo",
	ModelList: "https://gateway.qoder.com.cn/algo/api/v2/model/list?Encode=1",
	ChatStream: "https://gateway.qoder.com.cn/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1",
};

const here = dirname(fileURLToPath(import.meta.url));
const basePromptRaw = readFileSync(join(here, "baseprompt.json"), "utf8");

export function materializeTemplate() {
	let tmpl = basePromptRaw;
	for (const key of ["{UUID1}", "{UUID2}", "{UUID3}", "{UUID4}", "{UUID5}"]) {
		tmpl = tmpl.replaceAll(key, newUUID());
	}
	tmpl = tmpl.replaceAll("{TIME1}", String(Date.now()));
	return JSON.parse(tmpl);
}

/** GET userinfo with a dt- device token. */
export async function fetchUserInfo(token) {
	const response = await fetch(CN.Userinfo, {
		headers: { Authorization: `Bearer ${token}` },
		signal: AbortSignal.timeout(15_000),
	});
	if (!response.ok) throw new Error(`qoder userinfo [${response.status}]`);
	return response.json();
}

export function resolveOAuthUserId(userInfo) {
	return String(userInfo?.id ?? userInfo?.uid ?? userInfo?.user_id ?? "");
}

/** Build the COSY session from the desktop credential. */
export function buildSession(auth, installSalt = "") {
	const identity = {
		name: auth.user?.name ?? "",
		aid: auth.user?.id ?? "",
		uid: auth.user?.id ?? "",
		userType: auth.user?.userType ?? "personal_standard",
		securityOauthToken: auth.token,
		refreshToken: auth.refreshToken ?? "",
	};
	const seed = fingerprintSeed(identity.uid, auth.token);
	return newSession(identity, deriveMachineID(seed, installSalt), deriveMachineToken(seed, installSalt), deriveMachineType(seed, installSalt));
}

/** GET the model list via signed request; returns [{key, name, contextWindow, maxTokens, isReasoning}]. */
export async function fetchModels(sess) {
	const response = await fetch(CN.ModelList, {
		headers: buildHeaders(sess, CN.ModelList, "", "application/json"),
		signal: AbortSignal.timeout(20_000),
	});
	if (!response.ok) throw new Error(`qoder model list [${response.status}]`);
	const payload = await response.json();
	for (const category of ["assistant", "developer", "chat"]) {
		const rawList = payload?.[category];
		if (!Array.isArray(rawList) || rawList.length === 0) continue;
		const models = [];
		for (const m of rawList) {
			if (m?.enable !== true) continue;
			let contextWindow = 0;
			const cc = m?.context_config;
			if (cc && typeof cc === "object") {
				const configs = Object.values(cc);
				const def = configs.find((c) => c?.is_default === true) ?? configs[0];
				contextWindow = Number(def?.token_count) || 0;
			}
			if (!contextWindow) contextWindow = Number(m?.max_input_tokens) || 200_000;
			const isReasoning = m?.is_reasoning === true;
			models.push({
				id: String(m.key ?? ""),
				name: String(m.display_name ?? m.key ?? ""),
				contextWindow,
				maxTokens: isReasoning ? 32_768 : 16_384,
				isReasoning,
				priceFactor: Number(m?.price_factor) || 1,
			});
		}
		if (models.length > 0) return models;
	}
	throw new Error("qoder model list returned no models");
}

// ---- message building (bridge/messages.go) ----

function blankResponseMeta() {
	return {
		id: "",
		usage: {
			prompt_tokens: 0, completion_tokens: 0, total_tokens: 0,
			completion_tokens_details: { reasoning_tokens: 0 },
			prompt_tokens_details: { cached_tokens: 0 },
		},
	};
}

function buildUserMessage(text) {
	return {
		role: "user",
		content: "",
		contents: [{ type: "text", text }],
		response_meta: blankResponseMeta(),
		reasoning_content_signature: "",
	};
}

function buildStructuredMessage(role, text) {
	return { role, content: text, response_meta: blankResponseMeta(), reasoning_content_signature: "" };
}

function normalizeContent(msg) {
	const c = msg?.content;
	if (typeof c === "string") return c;
	if (c == null) return "";
	if (Array.isArray(c)) {
		return c.map((block) => (typeof block === "string" ? block : block?.text ?? "")).join("\n\n");
	}
	return JSON.stringify(c);
}

/**
 * Normalize an incoming role to one Qoder accepts.
 *
 * Qoder's upstream rejects anything outside
 * `['system', 'assistant', 'user', 'tool', 'function']` — notably the newer
 * OpenAI `developer` role (DSH sends it, and the upstream answers
 * "developer is not one of [...]" as a provider_error). `developer` means the
 * same thing as `system`, so it folds there; anything else unknown folds into
 * the user text so a future role name can never fail the whole request the way
 * Trae's flatten-to-text conversion never can.
 */
function qoderRoleOf(role) {
	if (role === "assistant" || role === "user" || role === "tool" || role === "function") return role;
	if (role === "system" || role === "developer") return "system";
	return "user";
}

/** Convert OpenAI messages into Qoder's structured message list. */
export function buildQoderMessages(templateMessages, incoming) {
	const rebuilt = [];
	const hasIncomingSystem = incoming.some((m) => qoderRoleOf(m?.role) === "system");
	if (!hasIncomingSystem && Array.isArray(templateMessages)) {
		for (const m of templateMessages) {
			if (qoderRoleOf(m?.role) === "system") rebuilt.push(structuredClone(m));
		}
	}
	for (const msg of incoming) {
		const role = qoderRoleOf(msg?.role);
		if (role === "user") {
			rebuilt.push(buildUserMessage(normalizeContent(msg)));
		} else if (role === "assistant" && Array.isArray(msg?.tool_calls) && msg.tool_calls.length > 0) {
			const out = buildStructuredMessage("assistant", normalizeContent(msg));
			out.tool_calls = msg.tool_calls;
			rebuilt.push(out);
		} else if (role === "tool" || role === "function") {
			const out = buildStructuredMessage("tool", normalizeContent(msg));
			if (typeof msg?.name === "string") out.name = msg.name;
			if (typeof msg?.tool_call_id === "string") out.tool_call_id = msg.tool_call_id;
			rebuilt.push(out);
		} else {
			const text = normalizeContent(msg);
			if (text !== "") rebuilt.push(buildStructuredMessage(role, text));
		}
	}
	return rebuilt;
}

/** Build one chat request body from the baseprompt template. */
export function buildChatBody(sess, model, messages, { isReasoning = false, maxTokens = 0 } = {}) {
	const body = materializeTemplate();
	const nid = newUUID();
	body.request_id = nid;
	body.chat_record_id = nid;
	body.request_set_id = newUUID();
	body.session_id = newUUID();
	body.stream = true;
	body.aliyun_user_type = sess.identity.userType;
	if (body.model_config && typeof body.model_config === "object") {
		body.model_config.key = model;
		if (isReasoning) body.model_config.is_reasoning = true;
	}
	if (maxTokens > 0 && body.parameters && typeof body.parameters === "object") {
		body.parameters.max_tokens = maxTokens;
	}
	// Business block: id/begin_at/name from the last user message.
	let prompt = "";
	for (let i = messages.length - 1; i >= 0; i--) {
		if (messages[i]?.role === "user") { prompt = normalizeContent(messages[i]); break; }
	}
	if (body.business && typeof body.business === "object") {
		body.business.id = newUUID();
		body.business.begin_at = Date.now();
		body.business.name = prompt.length > 30 ? prompt.slice(0, 30) : prompt;
	}
	if (body.chat_context && typeof body.chat_context === "object") {
		if (body.chat_context.text && typeof body.chat_context.text === "object") body.chat_context.text.text = prompt;
		if (body.chat_context.extra?.originalContent && typeof body.chat_context.extra.originalContent === "object") {
			body.chat_context.extra.originalContent.text = prompt;
		}
	}
	body.messages = messages;
	return body;
}

/** Read one SSE frame stream; yields data payload strings. */
async function* readSse(response) {
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			buffer += decoder.decode(value, { stream: true });
			for (;;) {
				const newline = buffer.indexOf("\n");
				if (newline < 0) break;
				const line = buffer.slice(0, newline).replace(/\r$/, "");
				buffer = buffer.slice(newline + 1);
				if (line.startsWith("data:")) yield line.slice(5).trim();
			}
		}
	} finally {
		reader.releaseLock();
	}
}

/** Extract deltas from one upstream envelope frame (bridge/delta.go). */
function extractDelta(dataLine) {
	let wrapper;
	try { wrapper = JSON.parse(dataLine); } catch { return {}; }
	const status = wrapper?.statusCodeValue;
	if (status !== undefined && Number(status) !== 200) {
		const detail = typeof wrapper?.body === "string" ? wrapper.body : JSON.stringify(wrapper).slice(0, 400);
		return { error: `qoder upstream envelope ${status}: ${detail}` };
	}
	const innerRaw = wrapper?.body;
	// Some upstream variants deliver the body as an already-parsed object
	// (and a few as the literal string "null" — MiniMax rounds do this on
	// their first frames). Normalize all three shapes instead of assuming a
	// JSON string, or the null case crashes on the business-code read below.
	let inner;
	if (innerRaw === null || innerRaw === undefined) return {};
	if (typeof innerRaw === "object") inner = innerRaw;
	else if (typeof innerRaw === "string") {
		if (innerRaw === "" || innerRaw === "null") return {};
		try { inner = JSON.parse(innerRaw); } catch { return {}; }
	} else return {};
	if (inner === null || typeof inner !== "object") return {};
	const usage = inner?.usage ?? {};
	const inputTokens = Number(usage.prompt_tokens) || 0;
	const outputTokens = Number(usage.completion_tokens) || 0;
	for (const ch of inner?.choices ?? []) {
		const delta = ch?.delta;
		if (!delta) continue;
		const piece = {
			role: typeof delta.role === "string" ? delta.role : "",
			text: typeof delta.content === "string" ? delta.content : "",
			reasoning: typeof delta.reasoning_content === "string" ? delta.reasoning_content : "",
			toolCalls: Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0 ? delta.tool_calls : undefined,
			inputTokens, outputTokens,
		};
		if (piece.role || piece.text || piece.reasoning || piece.toolCalls) return piece;
	}
	if (typeof inner.code === "string" && inner.code !== "" && inner.code !== "0") {
		return { error: `qoder upstream error code=${inner.code}: ${inner.message ?? ""}` };
	}
	if (inputTokens > 0 || outputTokens > 0) return { inputTokens, outputTokens };
	return {};
}

/** Stream one chat turn; yields {type:'text'|'reasoning'|'usage'|'done', …}. */
export async function* streamChat(sess, model, messages, signal, { isReasoning = false, maxTokens = 0 } = {}) {
	const templateMessages = materializeTemplate().messages;
	const qoderMessages = buildQoderMessages(templateMessages, messages);
	const body = buildChatBody(sess, model, qoderMessages, { isReasoning, maxTokens });
	const bodyStr = encode(Buffer.from(JSON.stringify(body), "utf8"));
	const response = await fetch(CN.ChatStream, {
		method: "POST",
		headers: { ...buildHeaders(sess, CN.ChatStream, bodyStr, "text/event-stream"), "x-model-key": model, "x-model-source": "system" },
		body: bodyStr,
		signal,
	});
	if (!response.ok) {
		const text = await response.text();
		throw new Error(`qoder chat [${response.status}]: ${text.slice(0, 400)}`);
	}
	let sawDone = false;
	try {
		for await (const data of readSse(response)) {
			if (data === "[DONE]") { sawDone = true; continue; }
			const piece = extractDelta(data);
			if (piece.error) throw new Error(piece.error);
			if (piece.role || piece.text) yield { type: "text", text: piece.text ?? "" };
			if (piece.reasoning) yield { type: "reasoning", text: piece.reasoning };
			if (piece.toolCalls) yield { type: "tool-calls", toolCalls: piece.toolCalls };
			if (piece.inputTokens > 0 || piece.outputTokens > 0) {
				yield { type: "usage", input: piece.inputTokens, output: piece.outputTokens };
			}
		}
	} finally {
		response.body?.cancel?.().catch?.(() => {});
	}
	yield { type: "done" };
}
