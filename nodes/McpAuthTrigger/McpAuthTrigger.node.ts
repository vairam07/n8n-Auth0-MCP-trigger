import {
  IWebhookFunctions,
  IWebhookResponseData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
} from 'n8n-workflow';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
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
        scopes: [],
        expiresAt,
        extra: { email: user['email'], userData: user },
      };
    },
  };
}

// ── The n8n node ──────────────────────────────────────────────────────────────
export class McpAuthTrigger implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'MCP Auth Trigger',
    name: 'mcpAuthTrigger',
    icon: 'fa:plug',
    group: ['trigger'],
    version: 1,
    description:
      'Real MCP Server (Streamable HTTP) with Auth0 Bearer token validation. ' +
      'Tool parameters are forwarded to your n8n workflow.',
    defaults: { name: 'MCP Auth Trigger' },
    inputs: [],
    // @ts-ignore
    outputs: ['main'],
    outputNames: ['Workflow'],
    webhooks: [
      {
        name: 'default',
        httpMethod: 'POST',
        responseMode: 'responseNode',
        path: '={{$parameter["path"]}}',
      },
    ],
    properties: [
      {
        displayName: 'Path',
        name: 'path',
        type: 'string',
        default: 'mcp',
        required: true,
        description: 'Webhook path for the MCP endpoint (e.g. "mcp" → /webhook/mcp)',
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
        description: 'Auth0 domain used to call /userinfo',
      },
      {
        displayName: 'Tool Name',
        name: 'toolName',
        type: 'string',
        default: 'get_eod_prices',
        required: true,
        description: 'MCP tool name Claude will call',
      },
      {
        displayName: 'Tool Description',
        name: 'toolDescription',
        type: 'string',
        typeOptions: { rows: 3 },
        default: 'Get end-of-day adjusted prices for NSE symbols',
        description: 'Description shown to the AI so it knows when to call this tool',
      },
      {
        displayName: 'Tool Parameters (JSON Schema properties)',
        name: 'toolSchema',
        type: 'json',
        default: JSON.stringify({
          symbols: {
            type: 'string',
            description: 'Comma-separated NSE symbols e.g. TCS,INFY',
          },
          lookback_days: {
            type: 'string',
            description: 'Number of calendar days to look back. Use 0 for a specific date.',
          },
          date: {
            type: 'string',
            description: 'Specific date YYYY-MM-DD. Only used when lookback_days is 0.',
          },
        }, null, 2),
        description: 'JSON Schema properties object (the fields inside "properties": {})',
      },
    ],
  };

  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject() as Request;
    const res = this.getResponseObject() as Response;

    const tokenValidation = this.getNodeParameter('tokenValidation', 'auth0') as string;
    const auth0Domain     = this.getNodeParameter('auth0Domain', '')           as string;
    const toolName        = this.getNodeParameter('toolName', 'tool')          as string;
    const toolDescription = this.getNodeParameter('toolDescription', '')       as string;
    const toolSchemaRaw   = this.getNodeParameter('toolSchema', '{}')          as string;

    // ── 1. Auth0 bearer validation ─────────────────────────────────────────
    if (tokenValidation === 'auth0') {
      const verifier   = makeAuth0Verifier(auth0Domain);
      const middleware = requireBearerAuth({ verifier });
      const passed     = await new Promise<boolean>((resolve) => {
        middleware(req, res, (err?: unknown) => resolve(!err));
      });
      if (!passed) return { noWebhookResponse: true };
    }

    const authInfo: AuthInfo | undefined = (req as any).auth;

    // ── 2. Parse tool schema ───────────────────────────────────────────────
    let schemaProperties: Record<string, unknown> = {};
    try {
      schemaProperties =
        typeof toolSchemaRaw === 'string'
          ? JSON.parse(toolSchemaRaw)
          : (toolSchemaRaw as Record<string, unknown>);
    } catch (_) {}

    const inputSchema = {
      type: 'object' as const,
      properties: schemaProperties,
    };

    // ── 3. Build MCP server with low-level request handlers ───────────────
    // We use setRequestHandler directly to avoid deep zod type inference issues
    const mcpServer = new McpServer({ name: toolName, version: '1.0.0' });
    const rawServer = mcpServer.server as any;

    // Promise that resolves when the tool is called with args
    let resolveToolCall!: (args: IDataObject) => void;
    const toolCallPromise = new Promise<IDataObject>((r) => { resolveToolCall = r; });

    // Promise that resolves when the workflow sends back a result
    let resolveWorkflowResult!: (result: unknown) => void;
    const workflowResultPromise = new Promise<unknown>((r) => { resolveWorkflowResult = r; });

    // Store resolveWorkflowResult so Respond to Webhook node can call it
    (req as any).__resolveWorkflowResult = resolveWorkflowResult;

    // tools/list handler
    rawServer.setRequestHandler(
      { method: 'tools/list' },
      async () => ({
        tools: [{ name: toolName, description: toolDescription, inputSchema }],
      }),
    );

    // tools/call handler
    rawServer.setRequestHandler(
      { method: 'tools/call' },
      async (request: { params: { name: string; arguments?: Record<string, unknown> } }) => {
        const args = (request.params.arguments ?? {}) as IDataObject;

        resolveToolCall({
          ...args,
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
        });

        // Wait for workflow result (set by Respond to Webhook node)
        const result = await workflowResultPromise;
        return {
          content: [{
            type: 'text' as const,
            text: typeof result === 'string' ? result : JSON.stringify(result),
          }],
        };
      },
    );

    // ── 4. Create Streamable HTTP transport ───────────────────────────────
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await mcpServer.connect(transport);

    // Handle the incoming MCP HTTP request
    await transport.handleRequest(req, res, req.body);

    // ── 5. Return workflow data if a tool was called ───────────────────────
    const raced = await Promise.race([
      toolCallPromise.then((data) => ({ type: 'tool' as const, data })),
      // Timeout fallback — if it was just tools/list or initialize
      new Promise<{ type: 'noop'; data: null }>((r) =>
        setTimeout(() => r({ type: 'noop', data: null }), 100),
      ),
    ]);

    if (raced.type === 'tool') {
      return { workflowData: [[{ json: raced.data }]] };
    }

    return { noWebhookResponse: true };
  }
}