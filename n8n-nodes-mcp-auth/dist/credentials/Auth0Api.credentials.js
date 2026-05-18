"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Auth0Api = void 0;
class Auth0Api {
    constructor() {
        this.name = 'auth0Api';
        this.displayName = 'Auth0 API';
        this.documentationUrl = 'https://auth0.com/docs';
        this.properties = [
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
}
exports.Auth0Api = Auth0Api;
//# sourceMappingURL=Auth0Api.credentials.js.map