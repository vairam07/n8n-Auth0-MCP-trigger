"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpAuthTrigger = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const undici_1 = require("undici");
const jose_1 = require("jose");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const index_js_1 = require("@modelcontextprotocol/sdk/server/index.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const zod_to_json_schema_1 = require("zod-to-json-schema");
// ── Convert Zod schema → plain JSON Schema ────────────────────────────────────
function toInputSchema(schema) {
    var _a;
    if (!schema)
        return { type: 'object', properties: {} };
    // Detect Zod v3 (_def) or Zod v4 (~standard vendor)
    const isZod = '_def' in schema ||
        ((_a = schema['~standard']) === null || _a === void 0 ? void 0 : _a.vendor) === 'zod';
    if (isZod) {
        try {
            return (0, zod_to_json_schema_1.zodToJsonSchema)(schema, { strictUnions: true });
        }
        catch {
            return { type: 'object', properties: {} };
        }
    }
    return schema;
}
// ── Token cache (1-day TTL, module-scoped so it survives across requests) ─────
const TOKEN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const tokenCache = new Map();
// ── JWKS sets are cached per Auth0 domain (module-scoped, `jose` handles its
// own internal key-fetch caching/rotation) ───────────────────────────────────
const jwksCache = new Map();
function getJwks(domain) {
    let jwks = jwksCache.get(domain);
    if (!jwks) {
        const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
        const fetchFn = proxyUrl
            ? (url, opts) => (0, undici_1.fetch)(url, { ...opts, dispatcher: new undici_1.ProxyAgent(proxyUrl) })
            : undefined;
        jwks = (0, jose_1.createRemoteJWKSet)(new URL(`https://${domain}/.well-known/jwks.json`), fetchFn ? { [jose_1.customFetch]: fetchFn } : undefined);
        jwksCache.set(domain, jwks);
    }
    return jwks;
}
// ── Validate token by verifying its signature against Auth0's JWKS ───────────
// Works for any RS256-signed access token regardless of audience — unlike
// calling /userinfo, which only accepts tokens scoped to the default OIDC
// audience and rejects tokens issued for a custom API audience.
async function validateWithAuth0(domain, token) {
    var _a, _b;
    if (!token) {
        return { valid: false, token: '', email: null, sub: null, userData: null, expiresAt: undefined, error: 'No token provided' };
    }
    // Return cached result if still within TTL
    const cacheKey = `${domain}:${token}`;
    const cached = tokenCache.get(cacheKey);
    if (cached && (Date.now() - cached.cachedAt) < TOKEN_CACHE_TTL_MS) {
        return cached.result;
    }
    // A JWE (encrypted) token has 5 dot-separated segments instead of a JWS's
    // 3, and can't be verified without the decryption key — only Auth0 and the
    // token's intended recipient have it. This usually means Auth0 issued an
    // ID token (or an access token with JWE encryption enabled) instead of a
    // verifiable API access token.
    if (token.split('.').length !== 3) {
        return {
            valid: false, token, email: null, sub: null, userData: null, expiresAt: undefined,
            error: 'Received an encrypted (JWE) token instead of a signed JWT access token. ' +
                'Check that the OAuth client is requesting/using the access_token (not id_token), ' +
                'and that it is scoped to an audience with JWE encryption disabled.',
        };
    }
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, getJwks(domain), {
            issuer: `https://${domain}/`,
        });
        const result = {
            valid: true,
            token,
            email: (_a = payload['email']) !== null && _a !== void 0 ? _a : null,
            sub: (_b = payload.sub) !== null && _b !== void 0 ? _b : null,
            userData: payload,
            expiresAt: payload.exp,
        };
        // Cache successful validations only
        tokenCache.set(cacheKey, { result, cachedAt: Date.now() });
        return result;
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { valid: false, token, email: null, sub: null, userData: null, expiresAt: undefined, error: msg };
    }
}
// ── Extract Bearer token from request ────────────────────────────────────────
function extractToken(req) {
    const authHeader = req.headers['authorization'] ||
        req.headers['Authorization'] || '';
    return authHeader.replace(/^Bearer\s+/i, '').trim();
}
// ── Node ──────────────────────────────────────────────────────────────────────
class McpAuthTrigger {
    constructor() {
        this.description = {
            displayName: 'MCP Auth Trigger',
            name: 'mcpAuthTrigger',
            icon: 'fa:plug',
            group: ['trigger'],
            version: 1,
            description: 'MCP Server Trigger with Auth0 Bearer token validation. ' +
                'Connect tools via the ai_tool port exactly like the native MCP Server Trigger.',
            defaults: { name: 'MCP Auth Trigger' },
            inputs: [
                {
                    type: n8n_workflow_1.NodeConnectionTypes.AiTool,
                    displayName: 'Tools',
                    required: false,
                },
            ],
            // @ts-ignore
            outputs: [],
            webhooks: [
                {
                    name: 'setup',
                    httpMethod: 'GET',
                    responseMode: 'onReceived',
                    isFullPath: true,
                    path: '={{$parameter["path"]}}',
                    // @ts-ignore
                    nodeType: 'mcp',
                    ndvHideMethod: true,
                    ndvHideUrl: false,
                },
                {
                    name: 'default',
                    httpMethod: 'POST',
                    responseMode: 'onReceived',
                    isFullPath: true,
                    path: '={{$parameter["path"]}}',
                    // @ts-ignore
                    nodeType: 'mcp',
                    ndvHideMethod: true,
                    ndvHideUrl: true,
                },
                {
                    name: 'default',
                    httpMethod: 'DELETE',
                    responseMode: 'onReceived',
                    isFullPath: true,
                    path: '={{$parameter["path"]}}',
                    // @ts-ignore
                    nodeType: 'mcp',
                    ndvHideMethod: true,
                    ndvHideUrl: true,
                },
            ],
            properties: [
                {
                    displayName: 'Path',
                    name: 'path',
                    type: 'string',
                    default: 'mcp-auth',
                    required: true,
                    description: 'The path for this MCP endpoint (e.g. "eod_prices" → /mcp/eod_prices)',
                },
                {
                    displayName: 'Token Validation',
                    name: 'tokenValidation',
                    type: 'options',
                    options: [
                        { name: 'None', value: 'none' },
                        { name: 'Auth0 /userinfo', value: 'auth0' },
                    ],
                    default: 'none',
                    description: 'How to validate the incoming Bearer token',
                },
                {
                    displayName: 'Auth0 Domain',
                    name: 'auth0Domain',
                    type: 'string',
                    default: '',
                    placeholder: 'your-tenant.us.auth0.com',
                    required: true,
                    displayOptions: { show: { tokenValidation: ['auth0'] } },
                    description: 'Auth0 domain for /userinfo validation',
                },
                {
                    displayName: 'Reject Invalid Tokens',
                    name: 'rejectInvalid',
                    type: 'boolean',
                    default: true,
                    displayOptions: { show: { tokenValidation: ['auth0'] } },
                    description: 'Return 401 immediately when token is invalid, or pass auth info downstream',
                },
            ],
        };
    }
    // ── Webhook handler ──────────────────────────────────────────────────────
    async webhook() {
        var _a, _b, _c, _d;
        const req = this.getRequestObject();
        const res = this.getResponseObject();
        const tokenValidation = this.getNodeParameter('tokenValidation', 'none');
        const auth0Domain = this.getNodeParameter('auth0Domain', '');
        const rejectInvalid = this.getNodeParameter('rejectInvalid', true);
        // ── 1. Validate token manually (no OAuth middleware) ──────────────────
        const rawToken = extractToken(req);
        let auth = {
            valid: true, token: rawToken, email: null, sub: null,
            userData: null, expiresAt: undefined,
        };
        if (tokenValidation === 'auth0') {
            auth = await validateWithAuth0(auth0Domain, rawToken);
            if (!auth.valid && rejectInvalid) {
                // Return 401 with WWW-Authenticate header — tells MCP client the
                // token is invalid without triggering OAuth discovery flow
                res.status(401)
                    .set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="Auth0 token validation failed"')
                    .json({
                    error: 'invalid_token',
                    error_description: (_a = auth.error) !== null && _a !== void 0 ? _a : 'Invalid or missing Bearer token',
                });
                return { noWebhookResponse: true };
            }
        }
        // ── 1b. Expose the token to connected tool nodes via execution custom
        // data — readable from any node in this run with
        // {{ $execution.customData.get("mcpAccessToken") }}, regardless of the
        // ai_tool connection type. This node has no main output, so `$('MCP Auth
        // Trigger').item` never resolves; customData is the only expression-
        // accessible channel available here.
        try {
            this.customData.set('mcpAccessToken', (_b = auth.token) !== null && _b !== void 0 ? _b : '');
            this.customData.set('mcpUserEmail', (_c = auth.email) !== null && _c !== void 0 ? _c : '');
            this.customData.set('mcpUserSub', (_d = auth.sub) !== null && _d !== void 0 ? _d : '');
        }
        catch {
            // customData requires a full execution context (runExecutionData) and
            // is unavailable when testing via "Listen for test event" in the NDV.
            // Token exposure via $execution.customData is best-effort — skip it
            // rather than fail the whole MCP request.
        }
        // ── 2. Load connected tools via ai_tool port ──────────────────────────
        const tools = (await this.getInputConnectionData(n8n_workflow_1.NodeConnectionTypes.AiTool, 0));
        // ── 3. Build MCP server ───────────────────────────────────────────────
        const server = new index_js_1.Server({ name: 'mcp-auth-trigger', version: '1.0.0' }, { capabilities: { tools: {} } });
        // tools/list
        server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => ({
            tools: tools.map((t) => ({
                name: t.name,
                description: t.description,
                inputSchema: toInputSchema(t.schema),
            })),
        }));
        // tools/call
        server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
            var _a, _b, _c, _d, _e, _f, _g;
            const { name, arguments: args = {} } = request.params;
            const tool = tools.find((t) => t.name === name);
            if (!tool) {
                return {
                    content: [{ type: 'text', text: `Tool "${name}" not found` }],
                    isError: true,
                };
            }
            // Inject auth info into tool params
            const callParams = {
                ...args,
                access_token: auth.token,
                _auth: {
                    token: auth.token,
                    email: auth.email,
                    sub: auth.sub,
                    userData: auth.userData,
                    expiresAt: auth.expiresAt,
                    tokenValid: auth.valid,
                },
            };
            // LangChain's base `Tool` class (e.g. a Code Tool with no declared
            // input schema) wraps its schema as `z.object({ input: z.string() })
            // .transform(...)` — a ZodEffects — and `.call()` only preserves a raw
            // string end-to-end; any object we pass is parsed against that
            // internal schema and everything but `input` is silently stripped.
            // `DynamicStructuredTool`s (e.g. HTTP Request Tool) use a plain
            // ZodObject instead — even an empty one — and require an object, not
            // a string. Declared JSON-schema property count can't tell these
            // apart (both can show zero properties), so check the Zod def shape
            // directly: only a ZodEffects-wrapped schema is safe to stringify.
            const schemaDef = tool.schema;
            const isStringInputTool = ((_a = schemaDef === null || schemaDef === void 0 ? void 0 : schemaDef._def) === null || _a === void 0 ? void 0 : _a.typeName) === 'ZodEffects';
            const callArg = isStringInputTool ? JSON.stringify(callParams) : callParams;
            // TEMPORARY DIAGNOSTIC — surfaces non-secret JWT claims (aud/scope/azp/
            // iss/exp) directly in the tool response so they can be compared
            // against what the downstream API expects, without exposing the
            // actual bearer token. Remove once the audience/scope mismatch is
            // resolved.
            const claims = (_b = auth.userData) !== null && _b !== void 0 ? _b : {};
            const debugPrefix = `[MCP-AUTH-DEBUG aud=${JSON.stringify((_c = claims['aud']) !== null && _c !== void 0 ? _c : null)} ` +
                `scope=${JSON.stringify((_d = claims['scope']) !== null && _d !== void 0 ? _d : null)} ` +
                `azp=${JSON.stringify((_e = claims['azp']) !== null && _e !== void 0 ? _e : null)} ` +
                `iss=${JSON.stringify((_f = claims['iss']) !== null && _f !== void 0 ? _f : null)} ` +
                `exp=${JSON.stringify((_g = claims['exp']) !== null && _g !== void 0 ? _g : null)}] `;
            try {
                const result = await tool.call(callArg);
                return {
                    content: [{
                            type: 'text',
                            text: debugPrefix + (typeof result === 'string' ? result : JSON.stringify(result)),
                        }],
                };
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                return {
                    content: [{ type: 'text', text: `${debugPrefix}Tool error: ${msg}` }],
                    isError: true,
                };
            }
        });
        // ── 4. Streamable HTTP transport ──────────────────────────────────────
        const transport = new streamableHttp_js_1.StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // stateless
        });
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return { noWebhookResponse: true };
    }
}
exports.McpAuthTrigger = McpAuthTrigger;
//# sourceMappingURL=McpAuthTrigger.node.js.map