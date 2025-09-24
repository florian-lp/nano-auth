import { cookies } from "next/headers";
import { AuthContext } from "./server";
import { issueAccessToken } from "./lib";

export function createAuthEndpoint(ctx: AuthContext<any, any>, errorUri: string) {

    return async (req: Request) => {
        const { get } = await cookies();
        const stateFromCookie = get('nano-state')?.value;

        const { searchParams } = new URL(req.url);
        const code = searchParams.get('code');
        const state = searchParams.get('state');

        try {
            if (ctx.dev.enabled) {
                await issueAccessToken(ctx, ctx.dev.user);
                
                return Response.redirect(new URL('/', req.url));
            }

            if (!code || state !== stateFromCookie) throw 'OAuth state mismatch';

            const [client, redirectTo] = Buffer.from(state.split('.')[0], 'hex').toString('utf8').split(/\./);
            const { authenticate, getUser } = ctx.oAuthClients[client];
            const { access_token } = await authenticate(code);
            if (!access_token) throw 'Could not authenticate oAuth user';

            const oAuthUser = await getUser(access_token);
            if (!oAuthUser) throw 'Could not fetch oAuth user data';

            const { user, error } = await ctx.retrieveUser(oAuthUser.id);
            if (error) throw error;

            if (!user) {
                await ctx.createUser(oAuthUser);
            } else {
                await issueAccessToken(ctx, user);
            }

            return Response.redirect(new URL(redirectTo, req.url));
        } catch (error) {
            if (typeof error !== 'string') error = 'An unexpected error occured';

            return Response.redirect(new URL(`${errorUri}?error=${error}`, req.url));
        }
    }
}