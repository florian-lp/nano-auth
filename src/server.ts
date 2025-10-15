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
    endpointUri: string;
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
    dev: {
        enabled: boolean;
        user: User;
    } | {
        enabled: false;
        user: null;
    };
};

export async function signInWith<T extends SupportedOAuthProviders>(ctx: AuthContext<T, any>, client: T, { redirectTo = '/', persist = true }: {
    redirectTo?: string;
    persist?: boolean;
} = {}) {
    if (ctx.dev.enabled && isDevEnvironment()) {
        return redirect(ctx.endpointUri.replace(/^(https?:\/\/)?.+?(\/)/, '/'));
    }

    const { set } = await cookies();
    const state = `${Buffer.from(`${client}:${persist}:${redirectTo}`, 'utf8').toString('hex')}.${crypto.randomBytes(16).toString('hex')}`;

    set('nano-state', state, {
        httpOnly: true
    });

    redirect(ctx.oAuthClients[client].grant(state));
}

export async function signOut(redirectTo = '/') {
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

export function createAuthInterface<P extends SupportedOAuthProviders, User extends { id: any; }>({ secretKey, endpointUri, errorUri, providers, retrieveUser, createUser, dev = { enabled: false, user: null } }: {
    secretKey: string;
    endpointUri: string;
    errorUri: string;
    providers: {
        [key in P]: Omit<OAuthClientConfig, 'redirectUri'>;
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
    dev?: {
        enabled: boolean;
        user: User;
    } | {
        enabled: false;
        user: null;
    };
}) {
    const ctx: AuthContext<P, User> = {
        secretkey: new TextEncoder().encode(secretKey),
        endpointUri,
        oAuthClients: {} as any,
        retrieveUser,
        createUser,
        dev
    };

    for (const provider in providers) {
        ctx.oAuthClients[provider] = supportedOAuthProviders[provider as P]({
            ...providers[provider as P],
            redirectUri: endpointUri
        });
    }

    return {
        signOut,
        revalidate: () => revalidate(ctx),
        getUser: cache(() => getUser(ctx)),
        signInWith: (client: P, options?: {
            persist?: boolean;
            redirectTo?: string;
        }) => signInWith(ctx, client, options),
        authEndpoint: createAuthEndpoint(ctx, errorUri)
    };
}