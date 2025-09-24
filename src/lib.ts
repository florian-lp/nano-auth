import { SignJWT } from "jose";
import { cookies } from "next/headers";
import { AuthContext } from "./server";

export async function issueAccessToken<User extends {}>(ctx: AuthContext<any, User>, user: User) {
    const { set } = await cookies();

    const accessToken = await new SignJWT(user)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(ctx.secretkey);

    set('nano-access-token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 604800
    });
}