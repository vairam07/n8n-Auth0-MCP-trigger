import {
  ICredentialType,
  INodeProperties,
} from 'n8n-workflow';

export class Auth0Api implements ICredentialType {
  name = 'auth0Api';
  displayName = 'Auth0 API';
  documentationUrl = 'https://auth0.com/docs';
  properties: INodeProperties[] = [
    {
      displayName: 'Auth0 Domain',
      name: 'domain',
      type: 'string',
      default: '',
      placeholder: 'your-tenant.us.auth0.com',
      description: 'Your Auth0 domain (without https://)',
      required: true,
    },
  ];
}
