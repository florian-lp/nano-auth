import { OAuthClients } from "./oauth";

// pass cookies methods

export function createAuthEndpoint() {

    return async (req: Request) => {
        const cookieState = ''; // todo

        const { searchParams } = new URL(req.url);
        const code = searchParams.get('code');
        const state = searchParams.get('state');

        try {
            if (!code || state !== cookieState) throw 'OAuth state mismatch';

            const [provider, redirectUrl] = Buffer.from(state.split('.')[0], 'hex').toString('utf8').split(/\./);
        } catch {
            return Response.redirect(new URL(req.url));
        }
    }
}

export function createAuthInterface<User extends {}>({ providers, secretKey, redirectUri }: {
    providers: (keyof typeof OAuthClients)[];
    secretKey: string;
    redirectUri: string;
}) {

    // create oAuth clients

    return {
        signIn() { },
        signOut() { },
        getUser() { },
        authEndpoint: createAuthEndpoint()
    };
}