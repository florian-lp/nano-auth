import { decodeJwt } from "jose";

export type OAuthClientConfig = {
    clientId: string;
    secret: string;
    redirectUri: string;
}

export type OAuthUser = {
    id: string;
    fullName: string;
    email: string;
    verified: boolean;
}

export type OAuthClient = {
    grant(state: string): string;
    authenticate(code: string): Promise<{ access_token?: string; }>;
    getUser(accessToken: string): Promise<OAuthUser | null>;
}

export function createOAuthProvider(
    grantUri: string,
    tokenUri: string,
    scopes: string[],
    callback: (req: (url: string) => Promise<any>) => Promise<OAuthUser | null>) {
    const postResponse = /apple/.test(tokenUri);
    const formEncoded = /discord|apple|microsoft|facebook/.test(tokenUri);

    const grantUrl = new URL(grantUri);
    grantUrl.searchParams.append('scope', scopes.join(' '));
    grantUrl.searchParams.append('response_type', 'code');
    if (postResponse) grantUrl.searchParams.append('response_mode', 'form_post');

    return ({ clientId, secret, redirectUri }: OAuthClientConfig): OAuthClient => ({
        grant(state: string) {
            grantUrl.searchParams.set('client_id', clientId);
            grantUrl.searchParams.set('state', state);
            grantUrl.searchParams.set('redirect_uri', redirectUri);

            return grantUrl.href;
        },
        async authenticate(code: string): Promise<{
            access_token?: string;
        }> {
            const body = {
                client_id: clientId,
                client_secret: secret,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri,
                code
            };

            const response = await fetch(tokenUri, {
                method: 'POST',
                body: formEncoded ? new URLSearchParams(body) : JSON.stringify(body),
                headers: {
                    'Content-Type': formEncoded ? 'application/x-www-form-urlencoded' : 'application/json',
                    Accept: 'application/json'
                }
            });

            const { id_token, access_token } = await response.json();

            return { access_token: id_token || access_token };
        },
        async getUser(access_token: string) {
            try {
                return await callback(async (url: string) => {
                    if (postResponse) return decodeJwt(access_token);

                    const response = await fetch(url, {
                        headers: {
                            Authorization: `Bearer ${access_token}`
                        }
                    });

                    return await response.json();
                });
            } catch {
                return null;
            }
        }
    });
}

export const supportedOAuthProviders = {
    apple: createOAuthProvider(
        'https://appleid.apple.com/auth/authorize',
        'https://appleid.apple.com/auth/token',
        ['name', 'email'],
        async (req) => {
            const { sub, email, email_verified } = await req('');

            return {
                id: `apple-${sub}`,
                fullName: email.replace(/@.+$/, ''),
                email,
                verified: email_verified
            };
        }
    ),
    discord: createOAuthProvider(
        'https://discord.com/oauth2/authorize',
        'https://discord.com/api/oauth2/token',
        ['identify', 'email'],
        async (req) => {
            const { id, username, email, verified } = await req('https://discord.com/api/users/@me');

            if (!email) return null;

            return {
                id: `discord-${id}`,
                fullName: username,
                email,
                verified
            };
        }
    ),
    facebook: createOAuthProvider(
        'https://www.facebook.com/v20.0/dialog/oauth',
        'https://graph.facebook.com/v20.0/oauth/access_token',
        ['email', 'public_profile'],
        async (req) => {
            const { id, name, email } = await req('https://graph.facebook.com/me?fields=id,name,email');

            if (!email) return null;

            return {
                id: `facebook-${id}`,
                fullName: name,
                email: email,
                verified: true
            };
        }
    ),
    github: createOAuthProvider(
        'https://github.com/login/oauth/authorize',
        'https://github.com/login/oauth/access_token',
        ['read:user', 'user:email'],
        async (req) => {
            const [{ id, name }, emails] = await Promise.all([
                req('https://api.github.com/user'),
                req('https://api.github.com/user/emails')
            ]);
            const { email = '', verified = false } = emails.find(({ primary }: any) => primary) || {};

            return {
                id: `github-${id}`,
                fullName: name,
                email,
                verified
            };
        }
    ),
    google: createOAuthProvider(
        'https://accounts.google.com/o/oauth2/v2/auth',
        'https://oauth2.googleapis.com/token',
        ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        async (req) => {
            const { sub, name, email, email_verified } = await req('https://www.googleapis.com/oauth2/v3/userinfo');

            return {
                id: `google-${sub}`,
                fullName: name,
                email,
                verified: email_verified
            };
        }
    ),
    microsoft: createOAuthProvider(
        'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        ['openid', 'profile', 'email'],
        async (req) => {
            const { sub, name, email, preferred_username } = await req('https://graph.microsoft.com/oidc/userinfo');

            return {
                id: `microsoft-${sub}`,
                fullName: name,
                email: email || preferred_username,
                verified: true
            };
        }
    )
}

export type SupportedOAuthProviders = keyof typeof supportedOAuthProviders;