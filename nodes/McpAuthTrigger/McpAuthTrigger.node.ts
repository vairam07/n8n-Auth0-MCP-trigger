import {
  IWebhookFunctions,
  IWebhookResponseData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
  NodeConnectionTypes,
} from 'n8n-workflow';

import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Request, Response } from 'express';
import { zodToJsonSchema } from 'zod-to-json-schema';

// ── Convert Zod schema → plain JSON Schema ────────────────────────────────────
function toInputSchema(schema: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!schema) return { type: 'object', properties: {} };
  // Detect Zod v3 (_def) or Zod v4 (~standard vendor)
  const isZod =
    '_def' in schema ||
    (schema['~standard'] as { vendor?: string } | undefined)?.vendor === 'zod';
  if (isZod) {
    try {
      return zodToJsonSchema(schema as never, { strictUnions: true }) as Record<string, unknown>;
    } catch {
      return { type: 'object', properties: {} };
    }
  }
  return schema;
}

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

// ── JWKS sets are cached per Auth0 domain (module-scoped, `jose` handles its
// own internal key-fetch caching/rotation) ───────────────────────────────────
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(domain: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(domain);
  if (!jwks) {
    const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
    const fetchFn  = proxyUrl
      ? (url: string, opts: object) => undiciFetch(url, { ...opts, dispatcher: new ProxyAgent(proxyUrl) } as Parameters<typeof undiciFetch>[1])
      : undefined;
    jwks = createRemoteJWKSet(
      new URL(`https://${domain}/.well-known/jwks.json`),
      fetchFn ? { [customFetch]: fetchFn as never } : undefined,
    );
    jwksCache.set(domain, jwks);
  }
  return jwks;
}

// ── Validate token by verifying its signature against Auth0's JWKS ───────────
// Works for any RS256-signed access token regardless of audience — unlike
// calling /userinfo, which only accepts tokens scoped to the default OIDC
// audience and rejects tokens issued for a custom API audience.
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
    const { payload } = await jwtVerify(token, getJwks(domain), {
      issuer: `https://${domain}/`,
    });

    const result: AuthResult = {
      valid:     true,
      token,
      email:     (payload['email'] as string) ?? null,
      sub:       (payload.sub as string) ?? null,
      userData:  payload as Record<string, unknown>,
      expiresAt: payload.exp,
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

    // ── 1. Validate token manually (no OAuth middleware) ──────────────────
    const rawToken = extractToken(req);
    let auth: AuthResult = {
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
            error:             'invalid_token',
            error_description: auth.error ?? 'Invalid or missing Bearer token',
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
      this.customData.set('mcpAccessToken', auth.token ?? '');
      this.customData.set('mcpUserEmail', auth.email ?? '');
      this.customData.set('mcpUserSub', auth.sub ?? '');
    } catch {
      // customData requires a full execution context (runExecutionData) and
      // is unavailable when testing via "Listen for test event" in the NDV.
      // Token exposure via $execution.customData is best-effort — skip it
      // rather than fail the whole MCP request.
    }

    // ── 2. Load connected tools via ai_tool port ──────────────────────────
    const tools = (await this.getInputConnectionData(
      NodeConnectionTypes.AiTool,
      0,
    )) as Array<{
      name:        string;
      description: string;
      schema?:     Record<string, unknown>;
      call:        (params: IDataObject | string) => Promise<IDataObject | string>;
    }>;

    // ── 3. Build MCP server ───────────────────────────────────────────────
    const server = new Server(
      { name: 'mcp-auth-trigger', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    // tools/list
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: tools.map((t) => ({
        name:        t.name,
        description: t.description,
        inputSchema: toInputSchema(t.schema),
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
      const schemaDef = tool.schema as { _def?: { typeName?: string } } | undefined;
      const isStringInputTool = schemaDef?._def?.typeName === 'ZodEffects';
      const callArg: IDataObject | string = isStringInputTool ? JSON.stringify(callParams) : callParams;

      // TEMPORARY DIAGNOSTIC — surfaces non-secret JWT claims (aud/scope/azp/
      // iss/exp) directly in the tool response so they can be compared
      // against what the downstream API expects, without exposing the
      // actual bearer token. Remove once the audience/scope mismatch is
      // resolved.
      const claims = auth.userData ?? {};
      const debugPrefix =
        `[MCP-AUTH-DEBUG aud=${JSON.stringify(claims['aud'] ?? null)} ` +
        `scope=${JSON.stringify(claims['scope'] ?? null)} ` +
        `azp=${JSON.stringify(claims['azp'] ?? null)} ` +
        `iss=${JSON.stringify(claims['iss'] ?? null)} ` +
        `exp=${JSON.stringify(claims['exp'] ?? null)}] `;

      try {
        const result = await tool.call(callArg);
        return {
          content: [{
            type: 'text' as const,
            text: debugPrefix + (typeof result === 'string' ? result : JSON.stringify(result)),
          }],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: 'text' as const, text: `${debugPrefix}Tool error: ${msg}` }],
          isError: true,
        };
      }
    });

    // ── 4. Streamable HTTP transport ──────────────────────────────────────
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    return { noWebhookResponse: true };
  }
}
