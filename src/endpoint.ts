import { cookies } from "next/headers";
import { AuthContext } from "./server";
import { isDevEnvironment, issueAccessToken } from "./lib";
import { AuthErrors } from "./error";

export function createAuthEndpoint(ctx: AuthContext<any, any>, errorUrl: string) {
    const errors = AuthErrors();

    return async (req: Request) => {
        const { get, set } = await cookies();
        const stateFromCookie = get('nano-state')?.value;

        try {
            const { searchParams } = new URL(req.url);
            let code = searchParams.get('code');
            let state = searchParams.get('state');

            if (req.method === 'POST') {
                const formData = await req.formData();

                code = formData.get('code') as string || code;
                state = formData.get('state') as string || state;
            }

            if (ctx.dev.enabled && isDevEnvironment()) {
                await issueAccessToken(ctx, ctx.dev.user);

                return Response.redirect(new URL('/', req.url), 303);
            }

            const isEmailLink = state === 'email';
            if (!code || (!isEmailLink && state !== stateFromCookie)) throw errors.code('invalid');

            let [client, persist, redirectTo] = isEmailLink ?
                ['email'] :
                Buffer.from(state!.split('.')[0], 'hex').toString('utf8').split(/:/);

            const { authenticate, getUser } = ctx.oAuthClients[client];
            const { access_token } = await authenticate(code);
            if (!access_token && isEmailLink) throw errors.code('expired');
            if (!access_token) throw errors.code('invalid');

            const oAuthUser = await getUser(access_token);
            if (!oAuthUser) throw errors.code('invalid');

            if (isEmailLink) {
                const payload = JSON.parse(access_token);

                persist = payload.persist;
                redirectTo = payload.redirectTo;
            }

            let { user, error } = await ctx.retrieveUser(oAuthUser.id);
            if (error) throw error;

            let url = new URL(redirectTo, req.url);
            url = new URL(url.pathname + url.search + url.hash, req.url);

            if (!user) {
                const created = await ctx.createUser(oAuthUser);
                if (created.error) throw created.error;

                ctx.onNewUser?.(user = created.user);
                if (ctx.onboardUrl) url = new URL(ctx.onboardUrl, req.url);
            }

            await issueAccessToken(ctx, user, persist === 'true');

            set('nano-last-used', client, {
                maxAge: 15552000
            });

            return Response.redirect(url, 303);
        } catch (error) {
            if (typeof error !== 'string') error = 'GE001';

            return Response.redirect(new URL(`${errorUrl}?error=${error}`, req.url), 303);
        }
    }
}