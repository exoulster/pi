import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { McpFetch } from "@earendil-works/pi-mcp";
import { McpOAuthAuthorizationRequiredError, type OAuthChallenge } from "@earendil-works/pi-mcp/oauth";
import lockfile from "proper-lockfile";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FileAuthStorageBackend } from "../src/core/auth-storage.ts";
import {
	createMcpAuthProvider,
	McpOAuthCredentialStore,
	type McpOAuthServerStore,
	type McpOAuthSettings,
	McpSignInCancelledError,
	type McpSignInPrompt,
	signInMcpServer,
} from "../src/extensions/mcp/oauth.ts";
import { startOAuthMcpServer } from "./suite/mcp-oauth-server.ts";

function barrier() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

// Regression coverage for #11135: rotating refreshes must be coordinated across sign-ins and connections.
describe("MCP sign-in refresh coordination", () => {
	const cleanups: (() => Promise<void> | void)[] = [];

	afterEach(async () => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
		while (cleanups.length > 0) await cleanups.pop()?.();
	});

	async function setup() {
		const server = await startOAuthMcpServer();
		const directory = mkdtempSync(join(tmpdir(), "pi-mcp-sign-in-refresh-"));
		cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
		cleanups.push(server.close);
		const store = () =>
			new McpOAuthCredentialStore(new FileAuthStorageBackend(join(directory, "mcp-auth.json")), directory).forServer(
				"test",
				server.url,
			);
		const browser: McpSignInPrompt = {
			showAuthorizationUrl: (url) => void fetch(url),
			promptForRedirectUrl: (signal) =>
				new Promise((resolve) => signal.addEventListener("abort", () => resolve(undefined), { once: true })),
		};
		const signIn = (
			credentials = store(),
			prompt = browser,
			options: { settings?: McpOAuthSettings; challenge?: OAuthChallenge; signal?: AbortSignal } = {},
		) => signInMcpServer({ serverUrl: server.url, store: credentials, settings: {}, prompt, ...options });
		await signIn();
		const connection = (credentials = store()) =>
			createMcpAuthProvider({
				serverUrl: server.url,
				store: credentials,
				settings: () => ({}),
				onChallenge: () => {},
			});
		const refresh = (credentials = store()) =>
			connection(credentials).onUnauthorized?.({
				response: new Response(null, { status: 401 }),
				serverUrl: new URL(server.url),
				fetch: globalThis.fetch,
				token: "access-1",
			});
		return { server, directory, store, browser, signIn, connection, refresh };
	}

	for (const [leader, follower, clientId] of [
		["connection", "sign-in", undefined],
		["sign-in", "connection", undefined],
		["sign-in", "sign-in", undefined],
		["sign-in", "sign-in", "client-1"],
	] as const) {
		it(`${clientId ? "serializes" : "shares"} a rotating refresh between ${leader} and ${follower}${clientId ? " with a configured client" : ""}`, async () => {
			const { server, directory, store, browser, signIn, refresh, connection } = await setup();
			const login = (credentials = store(), prompt = browser) =>
				signIn(credentials, prompt, { settings: { clientId } });
			const rotated = barrier();
			const release = barrier();
			const followerStarted = barrier();
			cleanups.push(release.resolve);
			const realFetch = globalThis.fetch;
			let refreshRequests = 0;
			const fetch: McpFetch = async (input, init) => {
				const isRefresh = init?.body instanceof URLSearchParams && init.body.get("grant_type") === "refresh_token";
				const number = isRefresh ? ++refreshRequests : 0;
				if (number === 2) followerStarted.resolve();
				const response = await realFetch(input, init);
				if (number === 1) {
					rotated.resolve();
					await release.promise;
				}
				return response;
			};
			vi.stubGlobal("fetch", fetch);
			const first = leader === "sign-in" ? login() : refresh();
			await rotated.promise;
			const credentials = store();
			// Observe the real file lock; the unfixed sign-in instead reaches a second HTTP refresh.
			const followerStore: McpOAuthServerStore = {
				...credentials,
				withRefreshLock: (fn, signal) => {
					followerStarted.resolve();
					return credentials.withRefreshLock(fn, signal);
				},
			};
			const opened: URL[] = [];
			const second =
				follower === "sign-in"
					? login(followerStore, {
							showAuthorizationUrl: (url) => opened.push(url),
							promptForRedirectUrl: async () => undefined,
						})
					: refresh(followerStore);
			const results = Promise.allSettled([first, second]);
			void Promise.resolve(second).then(followerStarted.resolve, followerStarted.resolve);
			await followerStarted.promise;
			release.resolve();
			expect(await results).toEqual([
				{ status: "fulfilled", value: undefined },
				{ status: "fulfilled", value: undefined },
			]);
			expect(refreshRequests).toBe(clientId ? 2 : 1);
			expect(opened).toEqual([]);
			expect((await store().load())?.tokens?.refresh_token).toBe(clientId ? "refresh-3" : "refresh-2");
			expect(await connection().token()).toBe(clientId ? "access-3" : "access-2");
			expect(server.tokenRequests.filter((request) => request.get("grant_type") === "refresh_token")).toHaveLength(
				clientId ? 2 : 1,
			);
			expect(readdirSync(directory)).toEqual(["mcp-auth.json"]);
		});
	}

	for (const recordedClient of [true, false]) {
		it(`does not accept another configured client's rotated grant (${recordedClient ? "registered" : "unrecorded"} identity)`, async () => {
			const { server, store, signIn } = await setup();
			const credentials = store();
			const initial = await credentials.load();
			if (!initial) throw new Error("Expected stored state");
			if (!recordedClient) {
				delete initial.clientInformation;
				await credentials.save(initial);
			}
			const rotated = barrier();
			const release = barrier();
			const waiting = barrier();
			cleanups.push(release.resolve);
			const requests: URLSearchParams[] = [];
			const owners = new Map([["refresh-1", "client-1"]]);
			let origin = "";
			// An external token endpoint enforces client binding before rotating a grant.
			const endpoint = createHttpServer((request, response) => {
				void (async () => {
					response.setHeader("content-type", "application/json");
					if (request.url === "/metadata") {
						response.end(
							JSON.stringify({
								issuer: origin,
								authorization_endpoint: new URL("/authorize", server.url).href,
								token_endpoint: `${origin}/token`,
								response_types_supported: ["code"],
								code_challenge_methods_supported: ["S256"],
								token_endpoint_auth_methods_supported: ["none"],
							}),
						);
						return;
					}
					const chunks: Buffer[] = [];
					for await (const chunk of request) chunks.push(Buffer.from(chunk));
					const params = new URLSearchParams(Buffer.concat(chunks).toString());
					requests.push(params);
					const refreshToken = params.get("refresh_token") ?? "";
					if (!owners.has(refreshToken) || owners.get(refreshToken) !== params.get("client_id")) {
						response.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
						return;
					}
					const upstream = await fetch(new URL("/token", server.url), { method: "POST", body: params });
					const tokens = (await upstream.json()) as { refresh_token: string };
					owners.delete(refreshToken);
					owners.set(tokens.refresh_token, params.get("client_id") ?? "");
					rotated.resolve();
					await release.promise;
					response.writeHead(upstream.status).end(JSON.stringify(tokens));
				})().catch((error: unknown) => response.writeHead(500).end(String(error)));
			});
			await new Promise<void>((resolve) => endpoint.listen(0, "127.0.0.1", resolve));
			cleanups.push(
				() =>
					new Promise<void>((resolve) => {
						endpoint.closeAllConnections();
						endpoint.close(() => resolve());
					}),
			);
			const address = endpoint.address();
			if (!address || typeof address === "string") throw new Error("Expected endpoint address");
			origin = `http://127.0.0.1:${address.port}`;
			const authServerMetadataUrl = new URL(`${origin}/metadata`);
			const first = signIn(store(), undefined, { settings: { clientId: "client-1", authServerMetadataUrl } });
			await rotated.promise;
			const follower = store();
			const opened: URL[] = [];
			const second = signIn(
				{
					...follower,
					withRefreshLock: (fn, signal) => {
						waiting.resolve();
						return follower.withRefreshLock(fn, signal);
					},
				},
				{
					showAuthorizationUrl: (url) => opened.push(url),
					promptForRedirectUrl: async () => undefined,
				},
				{ settings: { clientId: "client-B", authServerMetadataUrl } },
			);
			const refused = expect(second).rejects.toBeInstanceOf(McpSignInCancelledError);
			await waiting.promise;
			release.resolve();
			await first;
			await refused;
			expect(requests.map((params) => [params.get("client_id"), params.get("refresh_token")])).toEqual([
				["client-1", "refresh-1"],
				["client-B", "refresh-2"],
			]);
			expect(opened).toHaveLength(1);
			expect(opened[0].searchParams.get("client_id")).toBe("client-B");
			expect(server.tokenRequests.map((params) => params.get("grant_type"))).toEqual([
				"authorization_code",
				"refresh_token",
			]);
			expect((await store().load())?.tokens).toBeUndefined();
		});
	}

	it("shares a rotating refresh between two OS processes", async () => {
		const { server, directory, store } = await setup();
		const worker = join(directory, "sign-in.mjs");
		writeFileSync(
			worker,
			`
import { once } from "node:events";
import { FileAuthStorageBackend } from ${JSON.stringify(new URL("../src/core/auth-storage.ts", import.meta.url).href)};
import { McpOAuthCredentialStore, signInMcpServer } from ${JSON.stringify(new URL("../src/extensions/mcp/oauth.ts", import.meta.url).href)};
const [directory, serverUrl, role] = process.argv.slice(2);
const credentials = new McpOAuthCredentialStore(new FileAuthStorageBackend(directory + "/mcp-auth.json"), directory).forServer("test", serverUrl);
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
	if (role === "follower" && init?.body instanceof URLSearchParams && init.body.get("grant_type") === "refresh_token") process.send("waiting");
	const response = await realFetch(input, init);
	if (role === "leader" && init?.body instanceof URLSearchParams && init.body.get("grant_type") === "refresh_token") {
		process.send("rotated");
		await once(process, "message");
	}
	return response;
};
try {
	await signInMcpServer({ serverUrl, settings: {}, store: {
		...credentials,
		withRefreshLock: (fn, signal) => {
			process.send("waiting");
			return credentials.withRefreshLock(fn, signal);
		},
	}, prompt: {
		showAuthorizationUrl: () => { throw new Error("Unexpected browser authorization"); },
		promptForRedirectUrl: async () => undefined,
	} });
} catch (error) {
	console.error(error);
	process.exitCode = 1;
} finally {
	process.disconnect();
}
`,
		);
		const start = (role: string) => {
			const child = spawn(process.execPath, [worker, directory, server.url, role], {
				env: { HOME: directory, PI_CODING_AGENT_DIR: directory, PI_OFFLINE: "1" },
				stdio: ["ignore", "pipe", "pipe", "ipc"],
			});
			const waiting = barrier();
			const rotated = barrier();
			let errors = "";
			child.stderr?.on("data", (chunk: Buffer) => {
				errors += chunk.toString();
			});
			child.on("message", (message: unknown) => {
				if (message === "waiting") waiting.resolve();
				if (message === "rotated") rotated.resolve();
			});
			const exited = new Promise<{ code: number | null; errors: string }>((resolve, reject) => {
				child.once("error", reject);
				child.once("close", (code) => resolve({ code, errors }));
			});
			cleanups.push(async () => {
				if (child.exitCode === null) child.kill("SIGKILL");
				await exited;
			});
			return {
				child,
				exited,
				waitFor: (phase: "waiting" | "rotated") =>
					Promise.race([
						(phase === "waiting" ? waiting : rotated).promise,
						exited.then(({ code, errors }) => {
							throw new Error(`${role} exited (${code}) before ${phase}: ${errors}`);
						}),
					]),
			};
		};
		const leader = start("leader");
		await leader.waitFor("rotated");
		const follower = start("follower");
		await follower.waitFor("waiting");
		leader.child.send("release");
		const results = await Promise.all([leader.exited, follower.exited]);
		expect(results.map(({ code, errors }) => ({ code, errors: code === 0 ? "" : errors }))).toEqual([
			{ code: 0, errors: "" },
			{ code: 0, errors: "" },
		]);
		expect((await store().load())?.tokens?.refresh_token).toBe("refresh-2");
		expect(server.tokenRequests.map((params) => params.get("grant_type"))).toEqual([
			"authorization_code",
			"refresh_token",
		]);
	});

	it("cancels sign-in while another holder retains the lock and releases its abandoned acquisition", async () => {
		const { server, store, signIn } = await setup();
		const credentials = store();
		const held = barrier();
		const release = barrier();
		const waiting = barrier();
		cleanups.push(release.resolve);
		const holder = credentials.withRefreshLock(async () => {
			held.resolve();
			await release.promise;
		});
		await held.promise;
		const abandonedReleased = barrier();
		const realLock = lockfile.lock;
		vi.spyOn(lockfile, "lock").mockImplementationOnce(async (path, options) => {
			const unlock = await realLock(path, options);
			return async () => {
				await unlock();
				abandonedReleased.resolve();
			};
		});
		const controller = new AbortController();
		const login = signIn(
			{
				...store(),
				withRefreshLock: (fn, signal) => {
					waiting.resolve();
					return credentials.withRefreshLock(fn, signal);
				},
			},
			undefined,
			{ signal: controller.signal },
		);
		await waiting.promise;
		controller.abort();
		// Cancellation must finish before the holder releases the lock.
		await expect(login).rejects.toBeInstanceOf(McpSignInCancelledError);
		release.resolve();
		await holder;
		// Observe this exact abandoned handle being released before starting a competing acquisition.
		await abandonedReleased.promise;
		await credentials.withRefreshLock(async () => {});
		expect(server.tokenRequests).toHaveLength(1);
		expect((await store().load())?.tokens?.refresh_token).toBe("refresh-1");
	}, 5_000);

	it("re-reads scope under the lock and allows refresh while the user approves a step-up", async () => {
		const { store, signIn, refresh } = await setup();
		const credentials = store();
		const held = barrier();
		const release = barrier();
		const loaded = barrier();
		const shown = barrier();
		const approve = barrier();
		cleanups.push(release.resolve, approve.resolve);
		const update = credentials.withRefreshLock(async () => {
			held.resolve();
			await release.promise;
			const latest = await credentials.load();
			if (!latest?.tokens) throw new Error("Expected stored tokens");
			await credentials.save({ ...latest, tokens: { ...latest.tokens, scope: "issues:read issues:extra" } });
		});
		await held.promise;
		let authorizationUrl: URL | undefined;
		const login = signIn(
			{
				...store(),
				load: async () => {
					const snapshot = await credentials.load();
					loaded.resolve();
					return snapshot;
				},
			},
			{
				showAuthorizationUrl: (url) => {
					authorizationUrl = url;
					shown.resolve();
				},
				promptForRedirectUrl: async () => {
					await approve.promise;
					if (!authorizationUrl) throw new Error("Expected authorization URL");
					const response = await fetch(authorizationUrl, { redirect: "manual" });
					return response.headers.get("location") ?? undefined;
				},
			},
			{ settings: { scope: "configured:read" }, challenge: { error: "insufficient_scope", scope: "issues:write" } },
		);
		await loaded.promise;
		release.resolve();
		await update;
		await shown.promise;
		expect(authorizationUrl?.searchParams.get("scope")).toBe("configured:read issues:read issues:extra issues:write");
		// This must finish before approval; holding the refresh lock across the browser wait deadlocks it.
		await refresh();
		expect((await store().load())?.tokens?.access_token).toBe("access-2");
		approve.resolve();
		await login;
		expect((await store().load())?.tokens).toMatchObject({
			access_token: "access-3",
			scope: "configured:read issues:read issues:extra issues:write",
		});
	});

	it("does not exchange a superseded browser response or clear newer credentials", async () => {
		const { server, store, signIn } = await setup();
		const shown = barrier();
		const approve = barrier();
		cleanups.push(approve.resolve);
		let authorizationUrl: URL | undefined;
		const login = signIn(
			store(),
			{
				showAuthorizationUrl: (url) => {
					authorizationUrl = url;
					shown.resolve();
				},
				promptForRedirectUrl: async () => {
					await approve.promise;
					if (!authorizationUrl) throw new Error("Expected authorization URL");
					const response = await fetch(authorizationUrl, { redirect: "manual" });
					return response.headers.get("location") ?? undefined;
				},
			},
			{ challenge: { error: "insufficient_scope", scope: "issues:write" } },
		);
		await shown.promise;
		await signIn(store(), undefined, { settings: { clientId: "client-1" } });
		const newer = await store().load();
		const rejected = expect(login).rejects.toThrow("sign-in was replaced by another sign-in");
		approve.resolve();
		await rejected;
		expect(await store().load()).toEqual(newer);
		expect(newer?.tokens?.access_token).toBe("access-2");
		expect(server.tokenRequests.map((request) => request.get("grant_type"))).toEqual([
			"authorization_code",
			"refresh_token",
		]);
	});

	it("keeps fixed callback ports strict and replaces registration when a preferred port is occupied", async () => {
		const { server, store, signIn } = await setup();
		const redirect = server.registrations[0].redirect_uris as string[];
		const port = Number(new URL(redirect[0]).port);
		const occupied = createServer();
		await new Promise<void>((resolve) => occupied.listen(port, "127.0.0.1", resolve));
		cleanups.push(() => new Promise<void>((resolve) => occupied.close(() => resolve())));
		await expect(signIn(store(), undefined, { settings: { callbackPort: port } })).rejects.toMatchObject({
			code: "EADDRINUSE",
		});
		expect((await store().load())?.tokens?.access_token).toBe("access-1");
		await signIn();
		expect(server.registrations).toHaveLength(2);
		expect(server.registrations[1].redirect_uris).not.toEqual(redirect);
		expect(server.tokenRequests.map((request) => request.get("grant_type"))).toEqual([
			"authorization_code",
			"authorization_code",
		]);
		expect((await store().load())?.tokens?.access_token).toBe("access-2");
	});

	it("runs browser sign-in when the stored refresh token genuinely returns invalid_grant", async () => {
		const { server, store, signIn } = await setup();
		const credentials = store();
		const state = await credentials.load();
		if (!state?.tokens) throw new Error("Expected stored tokens");
		await credentials.save({ ...state, tokens: { ...state.tokens, refresh_token: "revoked" } });
		await signIn();
		expect(server.tokenRequests[1].get("refresh_token")).toBe("revoked");
		expect(server.authorizations).toHaveLength(2);
		expect((await store().load())?.tokens?.refresh_token).toBe("refresh-2");
	});

	it("requires sign-in after a rotated refresh response is lost, without recovering an unknown token", async () => {
		const { server, store, refresh, connection, signIn } = await setup();
		const realFetch = globalThis.fetch;
		let lost = false;
		const fetch: McpFetch = async (input, init) => {
			const response = await realFetch(input, init);
			if (!lost && init?.body instanceof URLSearchParams && init.body.get("grant_type") === "refresh_token") {
				lost = true;
				await response.text();
				throw new TypeError("Simulated lost refresh response");
			}
			return response;
		};
		vi.stubGlobal("fetch", fetch);
		await expect(refresh()).rejects.toBeInstanceOf(McpOAuthAuthorizationRequiredError);
		expect((await store().load())?.tokens?.refresh_token).toBe("refresh-1");
		// The server consumed refresh-1. Retrying cannot recover refresh-2 and invalid_grant clears the grant.
		await expect(refresh()).rejects.toBeInstanceOf(McpOAuthAuthorizationRequiredError);
		expect((await store().load())?.tokens).toBeUndefined();
		expect(await connection().token()).toBeUndefined();
		expect(server.tokenRequests.slice(1).map((request) => request.get("refresh_token"))).toEqual([
			"refresh-1",
			"refresh-1",
		]);
		await signIn();
		expect((await store().load())?.tokens?.access_token).toBe("access-3");
		expect(server.authorizations).toHaveLength(2);
	});
});
