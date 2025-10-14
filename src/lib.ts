import { SignJWT } from "jose";
import { cookies } from "next/headers";
import { AuthContext } from "./server";

export async function issueAccessToken<User extends {}>(ctx: AuthContext<any, User>, user: User, persist = true) {
    const { set } = await cookies();

    const accessToken = await new SignJWT(user)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(ctx.secretkey);

    set('nano-access-token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: persist ? 604800 : 0
    });
}

export function readCookies() {
    return document.cookie.split(';').reduce<{ [key: string]: string }>((cookies, cookie) => {
        const [key, value] = cookie.split('=');

        if (key && value) cookies[decodeURIComponent(key.trim())] = decodeURIComponent(value.trim());

        return cookies;
    }, {});
}

export const isDevEnvironment = () => process.env.NODE_ENV === 'development';