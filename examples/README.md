# Darboon client examples

[`darboon-client.ts`](darboon-client.ts) is a single, dependency-light TypeScript
client that exercises **every** client-facing Darboon flow:

- OIDC discovery + JWKS
- self-service registration, email/phone verification
- password login (incl. the **MFA** branch)
- OTP request + grant (passwordless login and MFA completion)
- rotating refresh + **reuse-detection** demo
- userinfo, logout, revoke, introspect
- password recovery (forgot / reset)
- Sign in with Google (build the redirect URL + consume the callback fragment)
- resource-service token verification against the JWKS

It uses only the global `fetch` (Node ≥ 18) and `readline`. `jose` is an optional
soft dependency used only by `verifyAccessToken()`.

## Run

Start Darboon (see the [root README](../README.md)), then:

```bash
# from the repo root
npx tsx examples/darboon-client.ts
```

Configure via env (sensible local defaults are built in):

```bash
DARBOON_URL=http://localhost:3000 \
CLIENT_ID=darboon-admin \
USERNAME=admin@example.com \
PASSWORD=change-me-immediately \
PHONE=+15551234567 \
ADMIN_API_KEY=your-admin-api-key \
npx tsx examples/darboon-client.ts
```

## Use as a library

```ts
import { DarboonClient, isMfaRequired } from './darboon-client';

const client = new DarboonClient('https://auth.domain.com', 's1');
const outcome = await client.loginPassword('ada@example.com', '•••••••');
if (!isMfaRequired(outcome)) {
  const me = await client.userinfo();
}
```
