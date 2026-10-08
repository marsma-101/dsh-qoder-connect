// index.js — dsh-qoder-connect plugin entry.
//
// Structure mirrors dsh-trae-connect: a loopback HTTP shim that speaks the
// OpenAI completions shape, a PiAiAdapter whose models point at that shim,
// and a settings Config card. Credentials are read from the Qoder CN
// desktop app's OSCrypt-encrypted local store — no OAuth interaction.

import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import z from "@deepseek-ai/schemastery";
import { createProvider } from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { PiAiAdapter } from "@deepseek-ai/dsh-llm-pi-ai";
import { resolveRetryPolicy } from "@deepseek-ai/dsh-llm";
import { QoderCredentialStore } from "./credentials.js";
import { buildSession, fetchModels, fetchUserInfo, streamChat } from "./upstream.js";

const QODER_PROVIDER = "qoder";
const QODER_STREAM_IDLE_TIMEOUT_MS = 300_000;
const NO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
const SHARED_SECRET = "qoder-connect-local";
const REQUEST_IMAGE_BUDGETS = {
	maxRequestImageBytes: 20_971_520,
	requestImagePixelBudget: 4_194_304,
	requestImageMaxBytes: 1_048_576,
};

export const Config = z.object({
	autoRefreshModels: z.boolean()
		.default(true)
		.volatile()
		.description("Refresh the Qoder model catalog every 10 minutes (on by default)"),
	dataDir: z.string()
		.default("")
		.volatile()
		.description("Explicit Qoder data directory (or auth.v1.dat path); overrides auto-discovery. Empty = scan %APPDATA%/com.qodercn.app.*"),
});

// QODER_DATA_DIR: explicit data-dir override (same value shape as dataDir).
const ENV_DATA_DIR = "QODER_DATA_DIR";

function readConfigValue(value) {
	if (value === null || value === undefined) return undefined;
	return typeof value.get === "function" ? value.get() : value;
}

const INERT_AUTH = {
	credentials: {
		async read() {},
		async list() {
			return [];
		},
		async modify() {
			throw new Error("dsh-qoder-connect: the qoder route has no pi-ai credential lifecycle");
		},
		async delete() {},
	},
	authContext: {
		async env() {},
		async fileExists() {
			return false;
		},
	},
};

function safeMessage(error) {
	return String(error?.message ?? error).slice(0, 300);
}

function writeJson(res, status, body) {
	res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
	res.end(JSON.stringify(body));
}

function writeOpenAIError(res, status, kind, message) {
	writeJson(res, status, { error: { message, type: kind, code: kind } });
}

function hostIsLoopback(host) {
	const name = String(host ?? "").split(":")[0]?.replace(/^\[/, "").replace(/\]$/, "") ?? "";
	return name === "localhost" || name === "127.0.0.1" || name === "::1" || name.startsWith("127.");
}

function originIsLoopback(origin) {
	if (origin === undefined || origin === "") return true;
	try {
		return hostIsLoopback(new URL(origin).host);
	} catch {
		return false;
	}
}

/** Live catalog: filled by the sync loop, fallback until the first success. */
let liveModels = [{ id: "auto", name: "Qoder Auto", contextWindow: 200_000, maxTokens: 32_768, isReasoning: true }];
export function currentModels() {
	return liveModels;
}

/**
 * Make sessionRef.current match the LATEST desktop credentials. Resolves the
 * credential store on every call; rebuilds the COSY session when there is no
 * session yet or the desktop app rotated the oauth token. Errors (resolve,
 * fetchUserInfo, buildSession) propagate to the caller.
 */
async function ensureSession(store, sessionRef, logger) {
	const auth = await store.resolve();
	if (sessionRef.current === undefined || sessionRef.current.identity.securityOauthToken !== auth.token) {
		const userInfo = await fetchUserInfo(auth.token);
		if (!auth.user?.id && userInfo?.id) auth.user = { ...(auth.user ?? {}), id: String(userInfo.id) };
		sessionRef.current = await buildSession(auth);
		logger.info?.(`dsh-qoder-connect: session (re)built for user ${auth.user?.name ?? auth.user?.id ?? "unknown"}`);
	}
	return sessionRef.current;
}

function createTraeStyleShim({ store, logger, sessionRef }) {
	let address = undefined;
	let readyResolve;
	let readyReject;
	const ready = new Promise((res, rej) => { readyResolve = res; readyReject = rej; });
	const server = createServer((req, res) => { void handle(req, res); });
	server.listen(0, "127.0.0.1");
	server.once("listening", () => { address = server.address(); readyResolve(); });
	server.once("error", (error) => readyReject(error));

	function bearerOk(req) {
		const match = /^Bearer\s+(.+)$/.exec(req.headers.authorization ?? "");
		return match !== null && match[1] === SHARED_SECRET;
	}

	async function handle(req, res) {
		try {
			const url = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
			if (!hostIsLoopback(req.headers.host)) {
				writeOpenAIError(res, 403, "host_not_allowed", "Host header must name the loopback interface");
				return;
			}
			if (!originIsLoopback(req.headers.origin)) {
				writeOpenAIError(res, 403, "origin_not_allowed", "Origin must be a loopback origin");
				return;
			}
			if (!bearerOk(req)) {
				writeOpenAIError(res, 401, "unauthorized", "missing or invalid Authorization bearer");
				return;
			}
			if (req.method === "GET" && (url === "/healthz" || url === "/healthz/")) {
				writeJson(res, 200, { ok: true });
				return;
			}
			if (req.method === "GET" && (url === "/v1/models" || url === "/v1/models/")) {
				writeJson(res, 200, {
					object: "list",
					data: currentModels().map((model) => ({ id: model.id, object: "model", created: 0, owned_by: "qoder" })),
				});
				return;
			}
			if (req.method === "POST" && (url === "/v1/chat/completions" || url === "/v1/chat/completions/")) {
				await chatCompletions(req, res);
				return;
			}
			writeOpenAIError(res, 404, "not_found", `no such route: ${req.method} ${url}`);
		} catch (error) {
			if (!res.headersSent) writeOpenAIError(res, 500, "internal", safeMessage(error));
			else res.end();
		}
	}

	async function readBody(req) {
		const chunks = [];
		for await (const chunk of req) chunks.push(chunk);
		return Buffer.concat(chunks).toString("utf8");
	}

	async function chatCompletions(req, res) {
		const contentType = String(req.headers["content-type"] ?? "");
		if (!contentType.includes("application/json")) {
			writeOpenAIError(res, 415, "unsupported_media_type", "Content-Type must be application/json");
			return;
		}
		let sess;
		try {
			sess = await ensureSession(store, sessionRef, logger);
		} catch (error) {
			writeOpenAIError(res, 401, "not_signed_in", safeMessage(error));
			return;
		}
		let body;
		try {
			body = JSON.parse(await readBody(req));
		} catch (error) {
			writeOpenAIError(res, 400, "invalid_request", `invalid JSON body: ${safeMessage(error)}`);
			return;
		}
		const model = String(body.model ?? "auto");
		const messages = Array.isArray(body.messages) ? body.messages : [];
		const stream = body.stream === true;
		const catalogEntry = currentModels().find((m) => m.id === model);
		const controller = new AbortController();
		req.on("close", () => controller.abort());

		try {
			const options = { isReasoning: catalogEntry?.isReasoning === true };
			if (stream) {
				// WorkBuddy's proven shape: build the WHOLE SSE body first, then
				// write it in one go (their shim pipes the upstream body wholesale).
				// Writing frame-by-frame let the harness see a stream that ended
				// without a finish_reason; assembling first removes that class of
				// failure entirely.
				const completionId = `chatcmpl-qoder-${Date.now().toString(36)}`;
				const created = Math.floor(Date.now() / 1000);
				const frames = [];
				const sendChunk = (delta, finishReason, usage) => {
					frames.push({
						id: completionId,
						object: "chat.completion.chunk",
						created,
						model,
						choices: [{ index: 0, delta, finish_reason: finishReason ?? null }],
						...(usage === undefined ? {} : { usage }),
					});
				};
				sendChunk({ role: "assistant" });
				let usage;
				let textTotal = 0;
				let failed;
				try {
					for await (const piece of streamChat(sess, model, messages, controller.signal, { ...options })) {
						if (piece.type === "text" && piece.text) { textTotal += piece.text.length; sendChunk({ content: piece.text }); }
						else if (piece.type === "reasoning") sendChunk({ reasoning_content: piece.text });
						else if (piece.type === "tool-calls") sendChunk({ tool_calls: piece.toolCalls });
						else if (piece.type === "usage") usage = piece;
					}
				} catch (error) {
					failed = error;
				}
				if (failed !== undefined && textTotal === 0) {
					writeOpenAIError(res, 502, "upstream_error", `qoder upstream: ${safeMessage(failed)}`);
					return;
				}
				sendChunk({}, "stop", usage === undefined ? undefined : {
					prompt_tokens: usage.input,
					completion_tokens: usage.output,
					total_tokens: usage.input + usage.output,
				});
				const payload = `${frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join("")}data: [DONE]\n\n`;
				res.writeHead(200, {
					"Content-Type": "text/event-stream",
					"Cache-Control": "no-cache",
					Connection: "keep-alive",
					"X-Accel-Buffering": "no",
				});
				res.end(payload);
			} else {
				let content = "";
				let reasoning = "";
				let toolCalls = [];
				let usage;
				for await (const piece of streamChat(sess, model, messages, controller.signal, { ...options })) {
					if (piece.type === "text") content += piece.text ?? "";
					else if (piece.type === "reasoning") reasoning += piece.text;
					else if (piece.type === "tool-calls") toolCalls = toolCalls.concat(piece.toolCalls);
					else if (piece.type === "usage") usage = piece;
				}
				writeJson(res, 200, {
					id: `chatcmpl-qoder-${Date.now().toString(36)}`,
					object: "chat.completion",
					created: Math.floor(Date.now() / 1000),
					model,
					choices: [{
						index: 0,
						message: { role: "assistant", content, ...(reasoning === "" ? {} : { reasoning_content: reasoning }), ...(toolCalls.length === 0 ? {} : { tool_calls: toolCalls }) },
						finish_reason: "stop",
					}],
					usage: usage === undefined ? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } : {
						prompt_tokens: usage.input,
						completion_tokens: usage.output,
						total_tokens: usage.input + usage.output,
					},
				});
			}
		} catch (error) {
			if (!res.headersSent) writeOpenAIError(res, 502, "upstream_error", `qoder upstream: ${safeMessage(error)}`);
			else { try { res.end(); } catch {} }
		}
	}

	return {
		ready,
		baseUrl: () => (address === undefined ? "" : `http://127.0.0.1:${address.port}`),
		token: () => SHARED_SECRET,
		close: () => new Promise((resolveClose, rejectClose) => {
			server.close(() => resolveClose());
			server.closeAllConnections();
			server.once("error", rejectClose);
		}),
	};
}

function thinkingLevelMapForReasoning() {
	// Qoder models toggle reasoning on/off via is_reasoning; no per-level
	// choices are declared upstream, so offer a single verified mapping.
	return null;
}

function toPiModel(info, baseUrl) {
	// Price display mirrors dsh-workbuddy-connect: free models get 「 · 免费」,
	// metered ones get the upstream price factor (e.g. 「 · x0.5」). The enable
	// flag is account-balance dependent, so models are never hidden for it.
	const priceSuffix = info.priceFactor === undefined || info.priceFactor === null
		? ""
		: info.priceFactor === 0 ? " · 免费" : ` · x${info.priceFactor}`;
	return {
		id: info.id,
		name: `${info.name}${priceSuffix}`,
		api: "openai-completions",
		provider: QODER_PROVIDER,
		baseUrl,
		input: ["text"],
		reasoning: info.isReasoning === true,
		cost: NO_COST,
		contextWindow: info.contextWindow,
		maxTokens: info.maxTokens,
		compat: { maxTokensField: "max_tokens" },
	};
}

function createQoderAdapter({ shim, logger, preferences }) {
	const buildModels = () => {
		const baseUrl = `${shim.baseUrl()}/v1`;
		const models = currentModels().map((info) => toPiModel(info, baseUrl));
		return models;
	};
	const provider = {
		...createProvider({
			id: QODER_PROVIDER,
			name: "Qoder",
			auth: { apiKey: {
				name: "Qoder COSY bearer token",
				async resolve({ credential }) {
					const apiKey = credential?.key;
					return apiKey === undefined || apiKey.length === 0 ? undefined : {
						auth: { apiKey },
						source: "Qoder",
					};
				},
			} },
			models: buildModels(),
			api: openAICompletionsApi(),
		}),
		getModels: () => buildModels(),
	};
	const profile = {
		provider: QODER_PROVIDER,
		displayName: "Qoder",
		streamIdleTimeoutMs: QODER_STREAM_IDLE_TIMEOUT_MS,
		retryPolicy: resolveRetryPolicy(undefined, "dsh-qoder-connect retryPolicy"),
		configuredMaxTokens: new Map(),
		modelErrors: new Map(),
		...REQUEST_IMAGE_BUDGETS,
		piProvider: provider,
	};
	const profiles = new Map([[QODER_PROVIDER, profile]]);
	const adapter = new PiAiAdapter({
		profiles: () => profiles,
		auth: INERT_AUTH,
		resolveApiKey: async () => shim.token(),
	});
	return {
		adapter,
		invalidate: () => {
			profiles.set(QODER_PROVIDER, { ...profile });
		},
	};
}

export async function apply(ctx, config) {
	const logger = ctx.logger;
	const preferences = {
		autoRefreshModels: () => readConfigValue(config?.autoRefreshModels) !== false,
		dataDir: () => {
			const fromEnv = process.env[ENV_DATA_DIR];
			if (typeof fromEnv === "string" && fromEnv.trim() !== "") return fromEnv;
			return readConfigValue(config?.dataDir);
		},
	};
	const store = new QoderCredentialStore({
		keyDir: resolve(join(process.env.DSH_HOME ?? join(homedir(), ".dsh"), ".qoder-connect")),
		dataDir: preferences.dataDir,
		logger,
	});
	const sessionRef = { current: undefined };
	const shim = createTraeStyleShim({ store, logger, sessionRef });
	try {
		await shim.ready;
	} catch (error) {
		logger.error("dsh-qoder-connect: Qoder loopback endpoint failed to start", error);
		return;
	}
	try {
		const qoder = createQoderAdapter({ shim, logger, preferences });
		const releaseAdapter = ctx.llm.registerAdapter([QODER_PROVIDER], qoder.adapter);
		try {
			ctx.effect(() => () => {
				releaseAdapter();
				shim.close();
			});
		} catch {
			releaseAdapter();
			shim.close();
		}
		try {
			ctx.on("loader/volatile-update", () => {
				qoder.invalidate();
				ctx.emit?.("llm/adapters-updated");
			});
		} catch {}
		// Sync loop: build the COSY session and refresh the live model roster.
		let lastModelIds = "";
		const syncCatalog = async () => {
			try {
				await ensureSession(store, sessionRef, logger);
				if (!preferences.autoRefreshModels() && liveModels.length > 1) return;
				const models = await fetchModels(sessionRef.current);
				const ids = models.map((m) => m.id).join(",");
				if (ids !== lastModelIds) {
					logger.info?.(`dsh-qoder-connect: catalog ${models.length} models`);
					liveModels = models;
					lastModelIds = ids;
					qoder.invalidate();
				}
			} catch (error) {
				logger.warn?.(`dsh-qoder-connect: catalog sync failed (${safeMessage(error)})`);
			}
		};
		void syncCatalog();
		const timer = setInterval(() => void syncCatalog(), 10 * 60 * 1000);
		timer.unref?.();
		try {
			ctx.effect(() => () => clearInterval(timer));
		} catch {
			clearInterval(timer);
		}
		// Settings-card status route (loopback-only).
		try {
			ctx.effect(() => {
				const dispose = ctx.webServer.register({
					kind: "exact",
					path: "/plugins/dsh-qoder-connect/status",
					handler: async (req, res) => {
						if (req.method !== "GET") { writeJson(res, 405, { error: "method not allowed" }); return; }
						if (!(hostIsLoopback(req.headers.host) && originIsLoopback(req.headers.origin))) {
							writeJson(res, 403, { error: "request-not-trusted" });
							return;
						}
						try {
							const authStatus = await store.status();
							writeJson(res, 200, { ...authStatus, models: currentModels().length });
						} catch (error) {
							writeJson(res, 500, { error: safeMessage(error) });
						}
					},
				});
				return () => dispose();
			}, "dsh-qoder-connect: Web status route");
		} catch {}
	} catch (error) {
		logger.error("dsh-qoder-connect: Qoder provider registration failed", error);
		shim.close();
	}
}

export const name = "dsh-qoder-connect";
export const inject = ["llm"];
