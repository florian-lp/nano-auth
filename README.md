# nano-auth

A super lightweight auth library for NextJS.

Currently supports the following OAuth providers:
- Discord
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
    endpointUri: 'https://mywebsite.com/authenticate',
    errorUri: '/sign-in',
    providers: {
        google: {
            clientId: '..',
            secret: process.env.GOOGLE_SECRET
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
```