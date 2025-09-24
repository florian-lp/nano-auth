import { SignJWT } from "jose";
import { cookies } from "next/headers";
import { AuthContext } from "./server";

export async function issueAccessToken(ctx: AuthContext<any, any>, user: any) {
    const { set } = await cookies();

    const accessToken = await new SignJWT(user)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(ctx.secretkey);

    set('access-token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: 604800
    });
}

// todo
export function sanitizeUserObject(ctx: AuthContext<any>, user: any) {
    const sanitized: any = {};

    for (const key in ctx.userSchema) {
        const schemaValue = ctx.userSchema[key];
        const values: string[] = Array.isArray(schemaValue) ? schemaValue : [schemaValue];

        const value = user[key];
        if (values.includes(value === null ? 'null' : typeof value)) sanitized[key] = value;
    }

    return sanitized as typeof ctx.userSchema;
}