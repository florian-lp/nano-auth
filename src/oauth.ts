export function createOAuthClient({ grantUri, tokenUri, scopes }: {
    grantUri: string;
    tokenUri: string;
    scopes: string[];
}) {
    const grantUrl = new URL(grantUri);
    grantUrl.searchParams.append('scope', scopes.join(' '));
    grantUrl.searchParams.append('response_type', 'code');

    return ({ clientId, secret, redirectUri, callback }: {
        clientId: string;
        secret: string;
        redirectUri: string;
        callback: (req: (url: string) => Promise<any>) => Promise<{
            id: string;
            name: string;
            email: string;
        }>;
    }) => ({
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
        getUser(access_token: string) {
            return callback(async (url: string) => {
                const response = await fetch(url, {
                    headers: {
                        Authorization: `Bearer ${access_token}`
                    }
                });

                return await response.json();
            });
        }
    });
}

export const OAuthClients = {
    discord: createOAuthClient({
        grantUri: 'https://discord.com/oauth2/authorize',
        tokenUri: 'https://discord.com/api/oauth2/token',
        scopes: ['identify', 'email']
    })
}