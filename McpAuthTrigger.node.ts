import {
  IWebhookFunctions,
  IWebhookResponseData,
  INodeType,
  INodeTypeDescription,
  IDataObject,
  NodeConnectionType,
} from 'n8n-workflow';

export class McpAuthTrigger implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'MCP Auth Trigger',
    name: 'mcpAuthTrigger',
    icon: 'fa:plug',
    group: ['trigger'],
    version: 1,
    description:
      'MCP Server Trigger that preserves and forwards the Authorization header downstream so you can validate JWT/Bearer tokens (e.g. Auth0) inside your workflow.',
    defaults: {
      name: 'MCP Auth Trigger',
    },
    inputs: [],
    // @ts-ignore — n8n allows string[] here at runtime
    outputs: ['main'],
    outputNames: ['Workflow'],
    webhooks: [
      {
        name: 'default',
        httpMethod: 'POST',
        responseMode: 'lastNode',
        path: '={{$parameter["path"]}}',
      },
    ],
    properties: [
      // ── Path ──────────────────────────────────────────────────────────
      {
        displayName: 'Path',
        name: 'path',
        type: 'string',
        default: 'mcp-auth',
        required: true,
        description:
          'The URL path this MCP endpoint listens on (e.g. "eod_prices" → /webhook/eod_prices)',
      },

      // ── Token Validation Mode ─────────────────────────────────────────
      {
        displayName: 'Token Validation',
        name: 'tokenValidation',
        type: 'options',
        options: [
          {
            name: 'None (pass token downstream only)',
            value: 'none',
          },
          {
            name: 'Validate with Auth0 /userinfo',
            value: 'auth0',
          },
          {
            name: 'Static Bearer Token',
            value: 'static',
          },
        ],
        default: 'none',
        description: 'How to validate the incoming Authorization header',
      },

      // ── Auth0 Domain (shown when auth0 selected) ──────────────────────
      {
        displayName: 'Auth0 Domain',
        name: 'auth0Domain',
        type: 'string',
        default: '',
        placeholder: 'your-tenant.us.auth0.com',
        required: true,
        displayOptions: {
          show: {
            tokenValidation: ['auth0'],
          },
        },
        description: 'Auth0 domain used to call /userinfo for token validation',
      },

      // ── Static Token (shown when static selected) ─────────────────────
      {
        displayName: 'Expected Token',
        name: 'staticToken',
        type: 'string',
        typeOptions: { password: true },
        default: '',
        required: true,
        displayOptions: {
          show: {
            tokenValidation: ['static'],
          },
        },
        description: 'The exact Bearer token value that must be present',
      },

      // ── Reject on invalid ─────────────────────────────────────────────
      {
        displayName: 'Reject Invalid Tokens',
        name: 'rejectInvalid',
        type: 'boolean',
        default: true,
        displayOptions: {
          show: {
            tokenValidation: ['auth0', 'static'],
          },
        },
        description:
          'Whether to return 401 immediately if validation fails, or pass failure info downstream',
      },

      // ── Response Mode ─────────────────────────────────────────────────
      {
        displayName: 'Response Mode',
        name: 'responseMode',
        type: 'options',
        options: [
          {
            name: 'Return Last Node Result',
            value: 'lastNode',
          },
          {
            name: 'Return Immediately (202 Accepted)',
            value: 'onReceived',
          },
        ],
        default: 'lastNode',
        description: 'When and what to respond to the MCP client',
      },
    ],
  };

  // ── Webhook handler ────────────────────────────────────────────────────────
  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject();
    const res = this.getResponseObject();

    const tokenValidation = this.getNodeParameter('tokenValidation', 'none') as string;
    const rejectInvalid = this.getNodeParameter('rejectInvalid', true) as boolean;

    // ── 1. Extract token from Authorization header ────────────────────────
    const authHeader =
      (req.headers['authorization'] as string) ||
      (req.headers['Authorization'] as string) ||
      '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();

    // ── 2. Parse incoming body ────────────────────────────────────────────
    let body: IDataObject = {};
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body as IDataObject) || {};
    } catch (_) {
      body = {};
    }

    // ── 3. Validate token based on mode ──────────────────────────────────
    let tokenValid = true;
    let tokenError = '';
    let userData: IDataObject = {};

    if (tokenValidation === 'static') {
      const expected = this.getNodeParameter('staticToken', '') as string;
      if (!token) {
        tokenValid = false;
        tokenError = 'No Authorization header provided';
      } else if (token !== expected) {
        tokenValid = false;
        tokenError = 'Bearer token does not match expected value';
      }
    } else if (tokenValidation === 'auth0') {
      const domain = this.getNodeParameter('auth0Domain', '') as string;
      if (!token) {
        tokenValid = false;
        tokenError = 'No Authorization header provided';
      } else {
        try {
          const response = await fetch(`https://${domain}/userinfo`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (response.ok) {
            userData = (await response.json()) as IDataObject;
          } else {
            tokenValid = false;
            tokenError = `Auth0 returned ${response.status}: ${response.statusText}`;
          }
        } catch (err: any) {
          tokenValid = false;
          tokenError = `Auth0 request failed: ${err.message}`;
        }
      }
    }

    // ── 4. Reject immediately if configured ──────────────────────────────
    if (!tokenValid && rejectInvalid) {
      res.status(401).json({
        error: 'Unauthorized',
        message: tokenError,
      });
      return { noWebhookResponse: true };
    }

    // ── 5. Build output — ALL headers + body + token info forwarded ───────
    const outputData: IDataObject = {
      // Original request body (tool params from MCP client)
      ...body,

      // Auth info — always forwarded so downstream nodes can use it
      _auth: {
        token,
        tokenValid,
        tokenError: tokenValid ? null : tokenError,
        validationMode: tokenValidation,
        userData: Object.keys(userData).length > 0 ? userData : null,
      },

      // Raw headers — full passthrough
      _headers: req.headers as IDataObject,

      // Convenience fields
      _method: req.method,
      _path: req.path,
    };

    return {
      workflowData: [[{ json: outputData }]],
    };
  }
}
