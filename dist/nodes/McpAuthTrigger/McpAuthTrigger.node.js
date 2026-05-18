"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpAuthTrigger = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const bearerAuth_js_1 = require("@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js");
const index_js_1 = require("@modelcontextprotocol/sdk/server/index.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
// ── Auth0 token verifier ──────────────────────────────────────────────────────
function makeAuth0Verifier(domain) {
    return {
        async verifyAccessToken(token) {
            var _a;
            const res = await fetch(`https://${domain}/userinfo`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) {
                throw new Error(`Auth0 rejected token: ${res.status} ${res.statusText}`);
            }
            const user = (await res.json());
            let expiresAt;
            try {
                const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
                expiresAt = payload.exp;
            }
            catch (_) { }
            return {
                token,
                clientId: (_a = user['sub']) !== null && _a !== void 0 ? _a : 'unknown',
                scopes: [],
                expiresAt,
                extra: { email: user['email'], userData: user },
            };
        },
    };
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
            // Accept ai_tool connections from toolWorkflow nodes
            inputs: [
                {
                    type: n8n_workflow_1.NodeConnectionTypes.AiTool,
                    displayName: 'Tools',
                    required: false,
                },
            ],
            // @ts-ignore — n8n runtime accepts string here
            outputs: ['main'],
            outputNames: ['Response'],
            webhooks: [
                {
                    name: 'setup',
                    httpMethod: 'GET',
                    responseMode: 'onReceived',
                    isFullPath: true,
                    path: '={{$parameter["path"]}}',
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
                    default: 'mcp',
                    required: true,
                    description: 'URL path for the MCP endpoint (e.g. "mcp" → /webhook/mcp)',
                },
                {
                    displayName: 'Token Validation',
                    name: 'tokenValidation',
                    type: 'options',
                    options: [
                        { name: 'None', value: 'none' },
                        { name: 'Auth0 /userinfo', value: 'auth0' },
                    ],
                    default: 'auth0',
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
                    description: 'Auth0 domain used to call /userinfo for token validation',
                },
                {
                    displayName: 'Reject Invalid Tokens',
                    name: 'rejectInvalid',
                    type: 'boolean',
                    default: true,
                    displayOptions: { show: { tokenValidation: ['auth0'] } },
                    description: 'Return 401 immediately when token is invalid or expired',
                },
            ],
        };
    }
    // ── Webhook handler ──────────────────────────────────────────────────────
    async webhook() {
        const req = this.getRequestObject();
        const res = this.getResponseObject();
        const tokenValidation = this.getNodeParameter('tokenValidation', 'auth0');
        const auth0Domain = this.getNodeParameter('auth0Domain', '');
        const rejectInvalid = this.getNodeParameter('rejectInvalid', true);
        // ── 1. Auth0 bearer validation ───────────────────────────────────────
        if (tokenValidation === 'auth0') {
            const verifier = makeAuth0Verifier(auth0Domain);
            const middleware = (0, bearerAuth_js_1.requireBearerAuth)({ verifier });
            const passed = await new Promise((resolve) => {
                middleware(req, res, (err) => resolve(!err));
            });
            if (!passed && rejectInvalid) {
                // requireBearerAuth already wrote the 401
                return { noWebhookResponse: true };
            }
        }
        const authInfo = req.auth;
        // ── 2. Load connected tools via ai_tool port ─────────────────────────
        // This is exactly what the native MCP Server Trigger does internally
        const tools = (await this.getInputConnectionData(n8n_workflow_1.NodeConnectionTypes.AiTool, 0));
        // ── 3. Build raw MCP Server with tool list + call handlers ───────────
        const server = new index_js_1.Server({ name: 'mcp-auth-trigger', version: '1.0.0' }, { capabilities: { tools: {} } });
        // tools/list — expose all connected tools to Claude
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
        // tools/call — call the matched tool and inject _auth into params
        server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
            var _a, _b, _c, _d, _e;
            const { name, arguments: args = {} } = request.params;
            const tool = tools.find((t) => t.name === name);
            if (!tool) {
                return {
                    content: [{ type: 'text', text: `Tool "${name}" not found` }],
                    isError: true,
                };
            }
            // Inject auth info so the sub-workflow can validate / use it
            const callParams = {
                ...args,
                access_token: (_a = authInfo === null || authInfo === void 0 ? void 0 : authInfo.token) !== null && _a !== void 0 ? _a : '',
                _auth: authInfo
                    ? {
                        token: authInfo.token,
                        clientId: authInfo.clientId,
                        email: (_c = (_b = authInfo.extra) === null || _b === void 0 ? void 0 : _b['email']) !== null && _c !== void 0 ? _c : null,
                        userData: (_e = (_d = authInfo.extra) === null || _d === void 0 ? void 0 : _d['userData']) !== null && _e !== void 0 ? _e : null,
                        expiresAt: authInfo.expiresAt,
                        tokenValid: true,
                    }
                    : { tokenValid: false },
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
        // ── 4. Streamable HTTP transport — handles MCP protocol ──────────────
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