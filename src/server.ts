import { jwtVerify } from "jose";
import { createAuthEndpoint } from "./endpoint";
import { OAuthClient, OAuthClientConfig, OAuthUser, supportedOAuthProviders, SupportedOAuthProviders } from "./oauth";
import crypto from 'crypto';
import { cache } from "react";
import { cookies } from 'next/headers';
import { redirect } from "next/navigation";
import { isDevEnvironment, issueAccessToken } from "./lib";
import { ErrorCode } from "./error";

export type AuthContext<P extends SupportedOAuthProviders, User extends { id: any; }> = {
    secretkey: Uint8Array<ArrayBuffer>;
    endpointUrl: string;
    onboardUrl?: string;
    oAuthClients: {
        [key in P]: OAuthClient;
    };
    retrieveUser: (id: string) => Promise<{
        user: User | null;
        error?: ErrorCode;
    }>;
    createUser: (oAuthUser: OAuthUser) => Promise<{
        user: User;
        error?: undefined;
    } | {
        user?: undefined;
        error: ErrorCode;
    }>;
    onNewUser?: (user: User) => Promise<void> | void;
    dev: {
        enabled: boolean;
        user: User;
    } | {
        enabled: false;
        user?: any;
    };
};

export async function signInWith<T extends SupportedOAuthProviders>(ctx: AuthContext<T, any>, client: T, { redirectTo = '/', persist = true }: {
    redirectTo?: string;
    persist?: boolean;
} = {}) {
    if (ctx.dev.enabled && isDevEnvironment()) {
        return redirect(ctx.endpointUrl.replace(/^(https?:\/\/)?.+?(\/)/, '/'));
    }

    const { set } = await cookies();
    const state = `${Buffer.from(`${client}:${persist}:${redirectTo}`, 'utf8').toString('hex')}.${crypto.randomBytes(16).toString('hex')}`;

    set('nano-state', state, {
        httpOnly: true
    });

    redirect(ctx.oAuthClients[client].grant(state));
}

export async function signOut(
    /**
     * Relative URL to redirect to after signing out.
     * 
     * @default /
     */
    redirectTo = '/'
) {
    const { delete: del } = await cookies();
    del('nano-access-token');

    redirect(redirectTo);
}

export async function getUser<User extends { id: any; }>(ctx: AuthContext<any, User>) {
    const { get } = await cookies();
    const accessToken = get('nano-access-token')?.value;
    if (!accessToken) return null;

    try {
        const { payload } = await jwtVerify(accessToken, ctx.secretkey);

        return payload as User;
    } catch {
        return null;
    }
}

export async function revalidate<User extends { id: any; }>(ctx: AuthContext<any, User>) {
    const { get, delete: del } = await cookies();
    const accessToken = get('nano-access-token')?.value;

    try {
        if (!accessToken) throw 0;

        const { payload, protectedHeader } = await jwtVerify<User>(accessToken, ctx.secretkey);
        const { user } = await ctx.retrieveUser(payload.id);
        if (!user) throw 0;

        await issueAccessToken(ctx, user, protectedHeader.persist as boolean);

        return user;
    } catch {
        del('nano-access-token');

        return null;
    }
}

export function createAuthInterface<P extends SupportedOAuthProviders, User extends { id: any; }>({ secretKey, endpointUrl, errorUrl, onboardUrl, providers, retrieveUser, createUser, onNewUser, dev = { enabled: false } }: {
    /**
     * JWT signing secret.
     */
    secretKey: string;
    /**
     * Absolute URL to redirect to after OAuth authorization.
     */
    endpointUrl: string;
    /**
     * Relative URL to redirect to upon failed sign in.
     */
    errorUrl: string;
    /**
     * Relative URL to redirect to upon succesful sign in of new user.
     */
    onboardUrl?: string;
    providers: {
        [key in P]: Omit<OAuthClientConfig, 'redirectUri'>;
    };
    /**
     * Should retrieve a user object by their id from your database.
     * 
     * @returns
     * The user or an {@link ErrorCode}.
     */
    retrieveUser: (id: string) => Promise<{
        user: User | null;
        error?: ErrorCode;
    }>;
    /**
     * Should create a new user in your database.
     * 
     * @returns
     * The created user or an {@link ErrorCode}.
     */
    createUser: (oAuthUser: OAuthUser) => Promise<{
        user: User;
        error?: undefined;
    } | {
        user?: undefined;
        error: ErrorCode;
    }>;
    /**
     * Callback which gets trigged when a new user first signs up.
     */
    onNewUser?: (user: User) => Promise<void> | void;
    dev?: {
        enabled: boolean;
        user: User;
    } | {
        enabled: false;
        user?: any;
    };
}) {
    const ctx: AuthContext<P, User> = {
        secretkey: new TextEncoder().encode(secretKey),
        endpointUrl,
        onboardUrl,
        oAuthClients: {} as any,
        retrieveUser,
        createUser,
        onNewUser,
        dev
    };

    for (const provider in providers) {
        ctx.oAuthClients[provider] = supportedOAuthProviders[provider as P]({
            ...providers[provider as P],
            redirectUri: endpointUrl
        });
    }

    return {
        signOut,
        revalidate: () => revalidate(ctx),
        getUser: cache(() => getUser(ctx)),
        signInWith: (client: P, options?: {
            /**
             * Relative URL to redirect to upon succesful sign in.
             * 
             * @default /
             */
            redirectTo?: string;
            /**
             * Whether to persist users' access token after they end their session (close their browser).
             * 
             * Persisted access tokens will be stored for a maximum of 7 days.
             * 
             * @default true
             */
            persist?: boolean;
        }) => signInWith(ctx, client, options),
        /**
         * Route handler function which should be exported as a POST request handler from a route.(ts|js) file.
         * 
         * The URL for the route handler should match your configured endpointUrl.
         */
        authEndpoint: createAuthEndpoint(ctx, errorUrl)
    };
}