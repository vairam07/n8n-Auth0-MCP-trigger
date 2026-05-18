import {
  IWebhookFunctions,
  IWebhookResponseData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
  NodeConnectionTypes,
} from 'n8n-workflow';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Request, Response } from 'express';

// ── Auth0 token verifier ──────────────────────────────────────────────────────
function makeAuth0Verifier(domain: string): OAuthTokenVerifier {
  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const res = await fetch(`https://${domain}/userinfo`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        throw new Error(`Auth0 rejected token: ${res.status} ${res.statusText}`);
      }
      const user = (await res.json()) as Record<string, unknown>;
      let expiresAt: number | undefined;
      try {
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64').toString(),
        ) as { exp?: number };
        expiresAt = payload.exp;
      } catch (_) {}
      return {
        token,
        clientId: (user['sub'] as string) ?? 'unknown',
        scopes:   [],
        expiresAt,
        extra: { email: user['email'], userData: user },
      };
    },
  };
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

    // Accept ai_tool connections from toolWorkflow nodes
    inputs: [
      {
        type:        NodeConnectionTypes.AiTool,
        displayName: 'Tools',
        required:    false,
      },
    ],
    // @ts-ignore — n8n runtime accepts string here
    outputs:     ['main'],
    outputNames: ['Response'],

    webhooks: [
      {
        name:         'setup',
        httpMethod:   'GET',
        responseMode: 'onReceived',
        isFullPath:   true,
        path:         '={{$parameter["path"]}}',
        nodeType:     'mcp',
        ndvHideMethod: true,
        ndvHideUrl:   false,
      },
      {
        name:         'default',
        httpMethod:   'POST',
        responseMode: 'onReceived',
        isFullPath:   true,
        path:         '={{$parameter["path"]}}',
        nodeType:     'mcp',
        ndvHideMethod: true,
        ndvHideUrl:   true,
      },
      {
        name:         'default',
        httpMethod:   'DELETE',
        responseMode: 'onReceived',
        isFullPath:   true,
        path:         '={{$parameter["path"]}}',
        nodeType:     'mcp',
        ndvHideMethod: true,
        ndvHideUrl:   true,
      },
    ],

    properties: [
      {
        displayName: 'Path',
        name:        'path',
        type:        'string',
        default:     'mcp',
        required:    true,
        description: 'URL path for the MCP endpoint (e.g. "mcp" → /webhook/mcp)',
      },
      {
        displayName: 'Token Validation',
        name:        'tokenValidation',
        type:        'options',
        options: [
          { name: 'None',               value: 'none'  },
          { name: 'Auth0 /userinfo',    value: 'auth0' },
        ],
        default:     'auth0',
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
        description: 'Auth0 domain used to call /userinfo for token validation',
      },
      {
        displayName: 'Reject Invalid Tokens',
        name:        'rejectInvalid',
        type:        'boolean',
        default:     true,
        displayOptions: { show: { tokenValidation: ['auth0'] } },
        description: 'Return 401 immediately when token is invalid or expired',
      },
    ],
  };

  // ── Webhook handler ──────────────────────────────────────────────────────
  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject() as Request;
    const res = this.getResponseObject() as Response;

    const tokenValidation = this.getNodeParameter('tokenValidation', 'auth0') as string;
    const auth0Domain     = this.getNodeParameter('auth0Domain', '')           as string;
    const rejectInvalid   = this.getNodeParameter('rejectInvalid', true)       as boolean;

    // ── 1. Auth0 bearer validation ───────────────────────────────────────
    if (tokenValidation === 'auth0') {
      const verifier   = makeAuth0Verifier(auth0Domain);
      const middleware = requireBearerAuth({ verifier });
      const passed     = await new Promise<boolean>((resolve) => {
        middleware(req, res, (err?: unknown) => resolve(!err));
      });
      if (!passed && rejectInvalid) {
        // requireBearerAuth already wrote the 401
        return { noWebhookResponse: true };
      }
    }

    const authInfo: AuthInfo | undefined = (req as any).auth;

    // ── 2. Load connected tools via ai_tool port ─────────────────────────
    // This is exactly what the native MCP Server Trigger does internally
    const tools = (await this.getInputConnectionData(
      NodeConnectionTypes.AiTool,
      0,
    )) as Array<{
      name:        string;
      description: string;
      schema?:     Record<string, unknown>;
      call:        (params: IDataObject) => Promise<IDataObject>;
    }>;

    // ── 3. Build raw MCP Server with tool list + call handlers ───────────
    const server = new Server(
      { name: 'mcp-auth-trigger', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    // tools/list — expose all connected tools to Claude
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: tools.map((t) => ({
        name:        t.name,
        description: t.description,
        inputSchema: t.schema ?? { type: 'object', properties: {} },
      })),
    }));

    // tools/call — call the matched tool and inject _auth into params
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;

      const tool = tools.find((t) => t.name === name);
      if (!tool) {
        return {
          content: [{ type: 'text' as const, text: `Tool "${name}" not found` }],
          isError: true,
        };
      }

      // Inject auth info so the sub-workflow can validate / use it
      const callParams: IDataObject = {
        ...(args as IDataObject),
        access_token: authInfo?.token ?? '',
        _auth: authInfo
          ? {
              token:      authInfo.token,
              clientId:   authInfo.clientId,
              email:      authInfo.extra?.['email'] ?? null,
              userData:   authInfo.extra?.['userData'] ?? null,
              expiresAt:  authInfo.expiresAt,
              tokenValid: true,
            }
          : { tokenValid: false },
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

    // ── 4. Streamable HTTP transport — handles MCP protocol ──────────────
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

    return { noWebhookResponse: true };
  }
}