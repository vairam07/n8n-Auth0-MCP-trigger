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

// ── Proxy-aware fetch, shared by JWKS lookups and the M2M token endpoint ─────
function getProxyAwareFetch(): typeof fetch {
  const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
  if (!proxyUrl) return fetch;
  return ((url: string, opts: object) =>
    undiciFetch(url, { ...opts, dispatcher: new ProxyAgent(proxyUrl) } as Parameters<typeof undiciFetch>[1])
  ) as unknown as typeof fetch;
}

// ── JWKS sets are cached per Auth0 domain (module-scoped, `jose` handles its
// own internal key-fetch caching/rotation) ───────────────────────────────────
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(domain: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(domain);
  if (!jwks) {
    jwks = createRemoteJWKSet(
      new URL(`https://${domain}/.well-known/jwks.json`),
      { [customFetch]: getProxyAwareFetch() as never },
    );
    jwksCache.set(domain, jwks);
  }
  return jwks;
}

// ── M2M client-credentials token cache (per domain+clientId+audience) ───────
// So the trigger can obtain its own access token, scoped to a downstream
// API's audience, instead of forwarding the caller's MCP-scoped token — an
// MCP client's token is deliberately scoped only to the MCP server itself
// (per the MCP authorization spec's resource-indicator requirement) and
// can't legitimately be replayed against unrelated APIs.
interface M2MTokenCacheEntry { accessToken: string; expiresAt: number }
const m2mTokenCache = new Map<string, M2MTokenCacheEntry>();

async function getM2MAccessToken(
  domain: string,
  clientId: string,
  clientSecret: string,
  audience: string,
): Promise<string> {
  const cacheKey = `${domain}:${clientId}:${audience}`;
  const cached = m2mTokenCache.get(cacheKey);
  // Refresh a bit before actual expiry to avoid races with in-flight requests
  if (cached && Date.now() < cached.expiresAt - 60_000) {
    return cached.accessToken;
  }

  const fetchFn = getProxyAwareFetch();
  const res = await fetchFn(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type:    'client_credentials',
      client_id:     clientId,
      client_secret: clientSecret,
      audience,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Auth0 client-credentials token request failed: ${res.status} ${res.statusText} ${body}`);
  }

  const data = (await res.json()) as { access_token: string; expires_in: number };
  m2mTokenCache.set(cacheKey, {
    accessToken: data.access_token,
    expiresAt:   Date.now() + data.expires_in * 1000,
  });

  return data.access_token;
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
          { name: 'None',                    value: 'none'  },
          { name: 'Auth0 (JWKS Signature)',  value: 'auth0' },
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
        description:
          'Auth0 domain used to verify incoming tokens (JWKS) and, if enabled below, ' +
          'to request the M2M token for the downstream API',
      },
      {
        displayName: 'Reject Invalid Tokens',
        name:        'rejectInvalid',
        type:        'boolean',
        default:     true,
        displayOptions: { show: { tokenValidation: ['auth0'] } },
        description: 'Return 401 immediately when token is invalid, or pass auth info downstream',
      },
      {
        displayName: 'Downstream Tool Access Token',
        name:        'downstreamAuthMode',
        type:        'options',
        options: [
          { name: 'Forward Caller\'s Token', value: 'forward' },
          { name: 'Client Credentials (M2M)', value: 'clientCredentials' },
        ],
        default:     'forward',
        description:
          'How to obtain the access_token exposed to connected tools. The caller\'s ' +
          'token is scoped only to this MCP server (per the MCP spec) and generally ' +
          'cannot be used against other APIs — use Client Credentials to have this ' +
          'node fetch its own token scoped to the downstream API instead.',
      },
      {
        displayName: 'M2M Client ID',
        name:        'm2mClientId',
        type:        'string',
        default:     '',
        required:    true,
        displayOptions: { show: { downstreamAuthMode: ['clientCredentials'] } },
        description: 'Client ID of an Auth0 Machine-to-Machine application authorized for the downstream API',
      },
      {
        displayName: 'M2M Client Secret',
        name:        'm2mClientSecret',
        type:        'string',
        typeOptions: { password: true },
        default:     '',
        required:    true,
        displayOptions: { show: { downstreamAuthMode: ['clientCredentials'] } },
        description: 'Client secret of the Auth0 M2M application',
      },
      {
        displayName: 'Downstream Audience',
        name:        'downstreamAudience',
        type:        'string',
        default:     '',
        placeholder: 'https://prod.zentropylabs.com',
        required:    true,
        displayOptions: { show: { downstreamAuthMode: ['clientCredentials'] } },
        description: 'Identifier of the downstream API to request a token for',
      },
    ],
  };

  // ── Webhook handler ──────────────────────────────────────────────────────
  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject() as Request;
    const res = this.getResponseObject() as Response;

    const tokenValidation     = this.getNodeParameter('tokenValidation', 'none')       as string;
    const auth0Domain        = this.getNodeParameter('auth0Domain', '')               as string;
    const rejectInvalid      = this.getNodeParameter('rejectInvalid', true)           as boolean;
    const downstreamAuthMode = this.getNodeParameter('downstreamAuthMode', 'forward') as string;

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

      // The caller's token is scoped only to this MCP server (a resource
      // indicator, per the MCP authorization spec) and generally cannot be
      // used against unrelated APIs. When enabled, fetch a separate M2M
      // token — scoped to the configured downstream audience — to expose to
      // this tool instead of forwarding the caller's own token. Done here,
      // per tool call, rather than once for the whole request: this handler
      // also serves the initial MCP handshake/discovery, which must succeed
      // even if the M2M credentials are misconfigured — only an actual tool
      // invocation should be able to fail on this.
      let toolAccessToken = auth.token;
      if (downstreamAuthMode === 'clientCredentials') {
        const m2mClientId        = this.getNodeParameter('m2mClientId', '')        as string;
        const m2mClientSecret    = this.getNodeParameter('m2mClientSecret', '')    as string;
        const downstreamAudience = this.getNodeParameter('downstreamAudience', '') as string;
        try {
          toolAccessToken = await getM2MAccessToken(auth0Domain, m2mClientId, m2mClientSecret, downstreamAudience);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          return {
            content: [{ type: 'text' as const, text: `Failed to obtain downstream API access token: ${msg}` }],
            isError: true,
          };
        }
      }

      // Inject auth info into tool params. access_token is whichever token
      // is appropriate for downstream calls (see downstreamAuthMode above);
      // _auth.token always reflects the caller's own validated identity.
      const callParams: IDataObject = {
        ...(args as IDataObject),
        access_token: toolAccessToken,
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

      try {
        const result = await tool.call(callArg);
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

    // ── 4. Streamable HTTP transport ──────────────────────────────────────
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    return { noWebhookResponse: true };
  }
}
