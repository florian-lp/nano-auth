import { cookies } from "next/headers";
import { AuthContext } from "./server";

export function createAuthEndpoint(ctx: AuthContext<any>, errorUri: string) {

    return async (req: Request) => {
        const { get } = await cookies();
        const stateFromCookie = get('nano-state')?.value;

        const { searchParams } = new URL(req.url);
        const code = searchParams.get('code');
        const state = searchParams.get('state');

        try {
            if (!code || state !== stateFromCookie) throw 'OAuth state mismatch';

            const [client, redirectTo] = Buffer.from(state.split('.')[0], 'hex').toString('utf8').split(/\./);
            const { authenticate, getUser } = ctx.oAuthClients[client];
            const { access_token } = await authenticate(code);
            if (!access_token) throw new Error('Could not authenticate oAuth user');

            const user = await getUser(access_token);
            if (!user) throw new Error('Could not fetch oAuth user data');

            
            // const user = await db.user.findUnique({
            //     where: {
            //         id: `${provider}-${id}`
            //     }
            // });
            // if (user && user.state === 'deleted') throw new Error('Your account has been deactivated');

            // user ?
            //     await issueAccessToken(user) :
            //     await createUser(`${provider}-${id}`, email, name);

            return Response.redirect(new URL(redirectTo, req.url));
        } catch {
            return Response.redirect(new URL(errorUri, req.url));
        }
    }
}