import { jwtVerify } from "jose";
import { createAuthEndpoint } from "./endpoint";
import { OAuthClient, OAuthClientConfig, OAuthUser, supportedOAuthProviders, SupportedOAuthProviders } from "./oauth";
import crypto from 'crypto';
import { cache } from "react";
import { cookies } from 'next/headers';
import { redirect } from "next/navigation";
import { issueAccessToken } from "./lib";

export type AuthContext<P extends SupportedOAuthProviders, User extends {}> = {
    secretkey: Uint8Array<ArrayBuffer>;
    endpointUri: string;
    oAuthClients: {
        [key in P]: OAuthClient;
    };
    retrieveUser: (id: string) => Promise<{
        user: User | null,
        error?: string;
    }>;
    createUser: (oAuthUser: OAuthUser) => Promise<User>;
    dev: {
        enabled: boolean;
        user: User;
    } | {
        enabled: false;
        user: null;
    };
};

export async function signInWith<T extends SupportedOAuthProviders>(ctx: AuthContext<T, any>, client: T, redirectTo: string) {
    if (ctx.dev.enabled) {
        const url = new URL(ctx.endpointUri);
        return redirect(url.pathname);
    }

    const { set } = await cookies();
    const state = `${Buffer.from(`${client}.${redirectTo}`, 'utf8').toString('hex')}.${crypto.randomBytes(16).toString('hex')}`;

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

export async function getUser<User extends {}>(ctx: AuthContext<any, User>) {
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

export async function revalidate<User extends {}>(ctx: AuthContext<any, User>) {
    const user = await getUser(ctx);

    if (user) {
        await issueAccessToken(ctx, user);
    } else {
        const { delete: del } = await cookies();

        del('nano-access-token');
    }

    return user;
}

export function createAuthInterface<P extends SupportedOAuthProviders, User extends {}>({ secretKey, endpointUri, errorUri, providers, retrieveUser, createUser, dev = { enabled: false, user: null } }: {
    secretKey: string;
    endpointUri: string;
    errorUri: string;
    providers: {
        [key in P]: Omit<OAuthClientConfig, 'redirectUri'>;
    };
    retrieveUser: (id: string) => Promise<{
        user: User | null;
        error?: string;
    }>;
    createUser: (oAuthUser: OAuthUser) => Promise<User>;
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
        revalidate,
        getUser: cache(() => getUser(ctx)),
        signInWith: (client: P, redirectTo = '/') => signInWith(ctx, client, redirectTo),
        authEndpoint: createAuthEndpoint(ctx, errorUri)
    };
}