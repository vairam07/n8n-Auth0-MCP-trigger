import {
  IWebhookFunctions,
  IWebhookResponseData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
  NodeConnectionTypes,
} from 'n8n-workflow';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Request, Response } from 'express';

// ── Auth info shape ───────────────────────────────────────────────────────────
interface AuthResult {
  valid:     boolean;
  token:     string;
  email:     string | null;
  sub:       string | null;
  userData:  Record<string, unknown> | null;
  expiresAt: number | undefined;
  error?:    string;
}

// ── Token cache (1-day TTL, module-scoped so it survives across requests) ─────
const TOKEN_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const tokenCache = new Map<string, { result: AuthResult; cachedAt: number }>();

// ── Validate token directly with Auth0 /userinfo ─────────────────────────────
async function validateWithAuth0(domain: string, token: string): Promise<AuthResult> {
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

    const user = (await res.json()) as Record<string, unknown>;

    // Decode JWT exp claim
    let expiresAt: number | undefined;
    try {
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64').toString(),
      ) as { exp?: number };
      expiresAt = payload.exp;
    } catch (_) {}

    const result: AuthResult = {
      valid:     true,
      token,
      email:     (user['email'] as string) ?? null,
      sub:       (user['sub'] as string)   ?? null,
      userData:  user,
      expiresAt,
    };

    // Cache successful validations only
    tokenCache.set(cacheKey, { result, cachedAt: Date.now() });

    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { valid: false, token, email: null, sub: null, userData: null, expiresAt: undefined, error: msg };
  }
}

// ── Extract Bearer token from request ────────────────────────────────────────
function extractToken(req: Request): string {
  const authHeader =
    (req.headers['authorization'] as string) ||
    (req.headers['Authorization'] as string) || '';
  return authHeader.replace(/^Bearer\s+/i, '').trim();
}

// ── Node ──────────────────────────────────────────────────────────────────────
export class McpAuthTrigger implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'MCP Auth Trigger',
    name:        'mcpAuthTrigger',
    icon:        'fa:plug',
    group:       ['trigger'],
    version:     1,
    description:
      'MCP Server Trigger with Auth0 Bearer token validation. ' +
      'Connect tools via the ai_tool port exactly like the native MCP Server Trigger.',
    defaults: { name: 'MCP Auth Trigger' },

    inputs: [
      {
        type:        NodeConnectionTypes.AiTool,
        displayName: 'Tools',
        required:    false,
      },
    ],
    // @ts-ignore
    outputs:     [],

    webhooks: [
      {
        name:          'setup',
        httpMethod:    'GET',
        responseMode:  'onReceived',
        isFullPath:    true,
        path:          '={{$parameter["path"]}}',
        // @ts-ignore
        nodeType:      'mcp',
        ndvHideMethod: true,
        ndvHideUrl:    false,
      },
      {
        name:          'default',
        httpMethod:    'POST',
        responseMode:  'onReceived',
        isFullPath:    true,
        path:          '={{$parameter["path"]}}',
        // @ts-ignore
        nodeType:      'mcp',
        ndvHideMethod: true,
        ndvHideUrl:    true,
      },
      {
        name:          'default',
        httpMethod:    'DELETE',
        responseMode:  'onReceived',
        isFullPath:    true,
        path:          '={{$parameter["path"]}}',
        // @ts-ignore
        nodeType:      'mcp',
        ndvHideMethod: true,
        ndvHideUrl:    true,
      },
    ],

    properties: [
      {
        displayName: 'Path',
        name:        'path',
        type:        'string',
        default:     'mcp-auth',
        required:    true,
        description: 'The path for this MCP endpoint (e.g. "eod_prices" → /mcp/eod_prices)',
      },
      {
        displayName: 'Token Validation',
        name:        'tokenValidation',
        type:        'options',
        options: [
          { name: 'None',            value: 'none'  },
          { name: 'Auth0 /userinfo', value: 'auth0' },
        ],
        default:     'none',
        description: 'How to validate the incoming Bearer token',
      },
      {
        displayName: 'Auth0 Domain',
        name:        'auth0Domain',
        type:        'string',
        default:     '',
        placeholder: 'your-tenant.us.auth0.com',
        required:    true,
        displayOptions: { show: { tokenValidation: ['auth0'] } },
        description: 'Auth0 domain for /userinfo validation',
      },
      {
        displayName: 'Reject Invalid Tokens',
        name:        'rejectInvalid',
        type:        'boolean',
        default:     true,
        displayOptions: { show: { tokenValidation: ['auth0'] } },
        description: 'Return 401 immediately when token is invalid, or pass auth info downstream',
      },
    ],
  };

  // ── Webhook handler ──────────────────────────────────────────────────────
  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject() as Request;
    const res = this.getResponseObject() as Response;

    const tokenValidation = this.getNodeParameter('tokenValidation', 'none')  as string;
    const auth0Domain     = this.getNodeParameter('auth0Domain', '')           as string;
    const rejectInvalid   = this.getNodeParameter('rejectInvalid', true)       as boolean;

    // ── 1. Determine if this request needs auth ──────────────────────────
    // MCP discovery messages (initialize, tools/list) are always allowed so
    // Claude can refresh the tool list without a token. Only tools/call
    // actually executes user-facing logic and must be protected.
    const body = req.body as IDataObject | undefined;
    const mcpMethod = typeof body?.method === 'string' ? body.method : '';
    const discoveryMethods = ['initialize', 'notifications/initialized', 'ping'];
    const isDiscovery = discoveryMethods.includes(mcpMethod);

    // ── 2. Validate token (skipped for discovery calls) ──────────────────
    let auth: AuthResult = {
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
            error:             'invalid_token',
            error_description: auth.error ?? 'Invalid or missing Bearer token',
          });
        return { noWebhookResponse: true };
      }
    }

    // ── 3. Load connected tools via ai_tool port ──────────────────────────
    const tools = (await this.getInputConnectionData(
      NodeConnectionTypes.AiTool,
      0,
    )) as Array<{
      name:        string;
      description: string;
      schema?:     Record<string, unknown>;
      call:        (params: IDataObject) => Promise<IDataObject>;
    }>;

    // ── 4. Build MCP server ───────────────────────────────────────────────
    const server = new Server(
      { name: 'mcp-auth-trigger', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    // tools/list
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: tools.map((t) => ({
        name:        t.name,
        description: t.description,
        inputSchema: t.schema ?? { type: 'object', properties: {} },
      })),
    }));

    // tools/call
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;

      const tool = tools.find((t) => t.name === name);
      if (!tool) {
        return {
          content: [{ type: 'text' as const, text: `Tool "${name}" not found` }],
          isError: true,
        };
      }

      // Inject auth info into tool params
      const callParams: IDataObject = {
        ...(args as IDataObject),
        access_token: auth.token,
        _auth: {
          token:      auth.token,
          email:      auth.email,
          sub:        auth.sub,
          userData:   auth.userData,
          expiresAt:  auth.expiresAt,
          tokenValid: auth.valid,
        },
      };

      try {
        const result = await tool.call(callParams);
        return {
          content: [{
            type: 'text' as const,
            text: typeof result === 'string' ? result : JSON.stringify(result),
          }],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: 'text' as const, text: `Tool error: ${msg}` }],
          isError: true,
        };
      }
    });

    // ── 5. Streamable HTTP transport ──────────────────────────────────────
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    return { noWebhookResponse: true };
  }
}