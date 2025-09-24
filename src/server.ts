import { jwtVerify } from "jose";
import { createAuthEndpoint } from "./endpoint";
import { OAuthClient, OAuthClientConfig, supportedOAuthProviders, SupportedOAuthProviders } from "./oauth";
import crypto from 'crypto';
import { cache } from "react";
import { cookies } from 'next/headers';
import { redirect } from "next/navigation";
import { issueAccessToken } from "./lib";

type UserValue = 'string' | 'boolean' | 'number' | 'null';

export type UserSchema = {
    [key: string]: UserValue | [UserValue, UserValue];
};

export const defaultUserSchema: UserSchema = {
    id: 'string',
    email: 'string'
}

export type AuthContext<P extends SupportedOAuthProviders, S extends UserSchema = typeof defaultUserSchema> = {
    secretkey: Uint8Array<ArrayBuffer>;
    oAuthClients: {
        [key in P]: OAuthClient;
    };
    userSchema: S;
};

export async function signInWith<T extends SupportedOAuthProviders>(ctx: AuthContext<T>, client: T, redirectTo = '/') {
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

export async function getUser(ctx: AuthContext<any>) {
    const { get } = await cookies();
    const accessToken = get('nano-access-token')?.value;
    if (!accessToken) return null;

    try {
        const { payload } = await jwtVerify(accessToken, ctx.secretkey);

        return payload as typeof ctx.userSchema;
    } catch {
        return null;
    }
}

export async function refreshUser() {
    const user = await getUser();

    await issueAccessToken();

    return user;
}

export function createAuthInterface<P extends SupportedOAuthProviders, S extends UserSchema>({ secretKey, redirectUri, errorUri, providers, userSchema }: {
    secretKey: string;
    redirectUri: string;
    errorUri: string;
    providers: {
        [key in P]: Omit<OAuthClientConfig, 'redirectUri'>;
    };
    userSchema?: S;
    retrieveUser: any;
    createUser: any;
}) {
    const ctx: AuthContext<P, S> = {
        oAuthClients: {},
        secretkey: new TextEncoder().encode(secretKey),
        userSchema: userSchema || defaultUserSchema
    };

    for (const provider in providers) {
        ctx.oAuthClients[provider] = supportedOAuthProviders[provider as T]({
            ...providers[provider as T],
            redirectUri
        });
    }

    return {
        signOut,
        signInWith: signInWith.bind({}, ctx),
        getUser: cache(getUser.bind({}, ctx)),
        authEndpoint: createAuthEndpoint(ctx, errorUri)
    };
}