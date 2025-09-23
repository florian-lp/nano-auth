import { SignJWT } from "jose";

export async function issueToken() {
    const accessToken = await new SignJWT(user)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(signingSecret);
}