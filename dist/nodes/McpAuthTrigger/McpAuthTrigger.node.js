"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpAuthTrigger = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const index_js_1 = require("@modelcontextprotocol/sdk/server/index.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
// ── Token cache (1-day TTL, module-scoped so it survives across requests) ─────
const TOKEN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const tokenCache = new Map();
// ── Validate token directly with Auth0 /userinfo ─────────────────────────────
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
    try {
        const res = await fetch(`https://${domain}/userinfo`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
            return {
                valid: false, token, email: null, sub: null, userData: null, expiresAt: undefined,
                error: `Auth0 /userinfo returned ${res.status}: ${res.statusText}`,
            };
        }
        const user = (await res.json());
        // Decode JWT exp claim
        let expiresAt;
        try {
            const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
            expiresAt = payload.exp;
        }
        catch (_) { }
        const result = {
            valid: true,
            token,
            email: (_a = user['email']) !== null && _a !== void 0 ? _a : null,
            sub: (_b = user['sub']) !== null && _b !== void 0 ? _b : null,
            userData: user,
            expiresAt,
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
        var _a;
        const req = this.getRequestObject();
        const res = this.getResponseObject();
        const tokenValidation = this.getNodeParameter('tokenValidation', 'none');
        const auth0Domain = this.getNodeParameter('auth0Domain', '');
        const rejectInvalid = this.getNodeParameter('rejectInvalid', true);
        // ── 1. Determine if this request needs auth ──────────────────────────
        // MCP discovery messages (initialize, tools/list) are always allowed so
        // Claude can refresh the tool list without a token. Only tools/call
        // actually executes user-facing logic and must be protected.
        const body = req.body;
        const mcpMethod = typeof (body === null || body === void 0 ? void 0 : body.method) === 'string' ? body.method : '';
        const discoveryMethods = ['initialize', 'notifications/initialized', 'ping'];
        const isDiscovery = discoveryMethods.includes(mcpMethod);
        // ── 2. Validate token (skipped for discovery calls) ──────────────────
        let auth = {
            valid: true, token: '', email: null, sub: null,
            userData: null, expiresAt: undefined,
        };
        if (tokenValidation === 'auth0' && !isDiscovery) {
            const token = extractToken(req);
            auth = await validateWithAuth0(auth0Domain, token);
            if (!auth.valid && rejectInvalid) {
                res.status(401)
                    .set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="Auth0 token validation failed"')
                    .json({
                    error: 'invalid_token',
                    error_description: (_a = auth.error) !== null && _a !== void 0 ? _a : 'Invalid or missing Bearer token',
                });
                return { noWebhookResponse: true };
            }
        }
        // ── 3. Load connected tools via ai_tool port ──────────────────────────
        const tools = (await this.getInputConnectionData(n8n_workflow_1.NodeConnectionTypes.AiTool, 0));
        // ── 4. Build MCP server ───────────────────────────────────────────────
        const server = new index_js_1.Server({ name: 'mcp-auth-trigger', version: '1.0.0' }, { capabilities: { tools: {} } });
        // tools/list
        server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => ({
            tools: tools.map((t) => {
                var _a;
                return ({
                    name: t.name,
                    description: t.description,
                    inputSchema: (_a = t.schema) !== null && _a !== void 0 ? _a : { type: 'object', properties: {} },
                });
            }),
        }));
        // tools/call
        server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
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
            try {
                const result = await tool.call(callParams);
                return {
                    content: [{
                            type: 'text',
                            text: typeof result === 'string' ? result : JSON.stringify(result),
                        }],
                };
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                return {
                    content: [{ type: 'text', text: `Tool error: ${msg}` }],
                    isError: true,
                };
            }
        });
        // ── 5. Streamable HTTP transport ──────────────────────────────────────
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