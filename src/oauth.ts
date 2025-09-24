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
    const grantUrl = new URL(grantUri);
    grantUrl.searchParams.append('scope', scopes.join(' '));
    grantUrl.searchParams.append('response_type', 'code');

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
            const formEncoded = /discord/.test(tokenUri);

            const response = await fetch(tokenUri, {
                method: 'POST',
                body: formEncoded ? new URLSearchParams(body) : JSON.stringify(body),
                headers: {
                    'Content-Type': formEncoded ? 'application/x-www-form-urlencoded' : 'application/json',
                    Accept: 'application/json'
                }
            });

            return await response.json();
        },
        async getUser(access_token: string) {
            try {
                return await callback(async (url: string) => {
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
    discord: createOAuthProvider(
        'https://discord.com/oauth2/authorize',
        'https://discord.com/api/oauth2/token',
        ['identify', 'email'],
        async (req) => {
            const { id, username, email, verified } = await req('https://discord.com/api/users/@me');

            return {
                id,
                fullName: username,
                email: email,
                verified
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
                id,
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
                id: sub,
                fullName: name,
                email,
                verified: email_verified
            };
        }
    )
}

export type SupportedOAuthProviders = keyof typeof supportedOAuthProviders;