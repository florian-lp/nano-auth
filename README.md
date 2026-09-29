# nano-auth

A super lightweight auth library for NextJS.

Currently supports the following OAuth providers:
- Apple
- Discord
- Facebook
- GitHub
- Google
- Microsoft

## Installation

```sh
$ npm i nano-auth
```

## Basic usage

### auth.ts
```ts
import { createAuthInterface } from 'nano-auth';

const auth = createAuthInterface({
    secretKey: process.env.SECRET,
    endpointUrl: 'https://mywebsite.com/authenticate',
    errorUrl: '/sign-in',
    providers: {
        google: {
            clientId: '..',
            secret: process.env.GOOGLE_SECRET
        },
        apple: {
            clientId: '..',
            secret: process.env.APPLE_CLIENT_SECRET // Signed ES256 JWT generated using .p8 key file
        }
    },
    async retrieveUser(id: string) {
        ..
    },
    async createUser({ id, email, fullName, verified }) {
        ..
    }
});

export const { authEndpoint, .. } = auth;
```

### app/authenticate/route.ts
```ts
import { authEndpoint } from "@/lib/auth";

export const GET = authEndpoint;

export const POST = authEndpoint; // Only required if you support Apple as a provider
```