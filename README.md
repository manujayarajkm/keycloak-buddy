# keycloak-buddy

An assistive TypeScript package for interacting with Keycloak Admin REST APIs. Provides strong typing, code completion, and easy-to-use methods for managing users, clients, realms, and more.

## Features

- Full TypeScript support with type declarations
- Auto code completion and suggestions
- Covers major Keycloak Admin REST API endpoints
- Easy error handling with structured error objects

## Installation

```bash
npm install keycloak-buddy
```

## Node.js Compatibility

- Minimum supported Node.js version: **16.x**

## Keycloak Compatibility

- Tested with Keycloak v21.x and v22.x

### Compatibility Matrix

|    Package     | Keycloak 21.x | Keycloak 22.x | Node.js 14.x | Node.js 16.x | Node.js 18.x |
| :------------: | :-----------: | :-----------: | :----------: | :----------: | :----------: |
| keycloak-buddy |      ✅       |      ✅       |      ❌      |      ✅      |      ✅      |

## Usage Example

```typescript
import { KeycloakAdmin } from "keycloak-buddy";

const keycloakAdmin = new KeycloakAdmin({
  baseUrl: "https://keycloak.example.com/auth",
  realm: "master",
  clientId: "admin-cli",
  username: "admin",
  password: "yourpassword",
});

* Do not forget to include the '/auth' part at the end of baseUrl

await keycloakAdmin.init();
const users = await keycloakAdmin.getUsers();
```

## API Reference

### User APIs

#### `getUsers()`

**Input:** None

**Output:** Array of user objects

```typescript
const users = await keycloakAdmin.getUsers();
```

#### `getUser(userId: string)`

**Input:** `userId` (string)

**Output:** User object

```typescript
const user = await keycloakAdmin.getUser("user-uuid");
```

#### `createUser(user: KeycloakUser)`

**Input:** `user` (KeycloakUser interface)

**Output:** Created user object

```typescript
const newUser = await keycloakAdmin.createUser({
  username: "alice",
  email: "alice@example.com",
});
```

#### `updateUser(userId: string, user: KeycloakUser)`

**Input:** `userId` (string), `user` (KeycloakUser interface)

**Output:** Updated user object

```typescript
await keycloakAdmin.updateUser("user-uuid", { email: "alice@newdomain.com" });
```

#### `deleteUser(userId: string)`

**Input:** `userId` (string)

**Output:** Success response

```typescript
await keycloakAdmin.deleteUser("user-uuid");
```

#### `resetUserPassword(userId: string, password: string, temporary?: boolean)`

**Input:** `userId` (string), `password` (string), `temporary` (boolean, optional)

**Output:** Success response

```typescript
await keycloakAdmin.resetUserPassword("user-uuid", "newPassword", true);
```

#### `sendVerifyEmail(userId: string)`

**Input:** `userId` (string)

**Output:** Success response

```typescript
await keycloakAdmin.sendVerifyEmail("user-uuid");
```

#### `getUserSessions(userId: string)`

**Input:** `userId` (string)

**Output:** Array of session objects

```typescript
const sessions = await keycloakAdmin.getUserSessions("user-uuid");
```

#### `logoutUser(userId: string)`

**Input:** `userId` (string)

**Output:** Success response

```typescript
await keycloakAdmin.logoutUser("user-uuid");
```

### Client APIs

#### `getClients()`

**Input:** None

**Output:** Array of client objects

```typescript
const clients = await keycloakAdmin.getClients();
```

#### `getClient(clientId: string)`

**Input:** `clientId` (string)

**Output:** Client object

```typescript
const client = await keycloakAdmin.getClient("client-uuid");
```

#### `createClient(client: KeycloakClient)`

**Input:** `client` (KeycloakClient interface)

**Output:** Created client object

```typescript
const newClient = await keycloakAdmin.createClient({
  clientId: "my-app",
  publicClient: true,
});
```

#### `updateClient(clientId: string, client: KeycloakClient)`

**Input:** `clientId` (string), `client` (KeycloakClient interface)

**Output:** Updated client object

```typescript
await keycloakAdmin.updateClient("client-uuid", {
  description: "Updated description",
});
```

#### `deleteClient(clientId: string)`

**Input:** `clientId` (string)

**Output:** Success response

```typescript
await keycloakAdmin.deleteClient("client-uuid");
```

#### `updateClientAttribute(clientId: string, attributeName: string, value: any)`

**Input:** `clientId` (string), `attributeName` (string), `value` (any)

**Output:** Updated client object

```typescript
await keycloakAdmin.updateClientAttribute(
  "client-uuid",
  "accessTokenLifespan",
  "3600"
);
```

#### `updateClientAccessTokenLifespan(clientId: string, lifespan: number)`

**Input:** `clientId` (string), `lifespan` (number)

**Output:** Updated client object

```typescript
await keycloakAdmin.updateClientAccessTokenLifespan("client-uuid", 3600);
```

### Realm APIs

#### `getRealm()`

**Input:** None

**Output:** Realm object

```typescript
const realm = await keycloakAdmin.getRealm();
```

## Error Handling

All methods throw errors in the following format:

```typescript
throw new Error(
  JSON.stringify({
    code: number,
    message: string,
    stack: string,
  })
);
```

### How to Handle Errors

You should always wrap your calls in a try/catch block and parse the error message:

```typescript
try {
  await keycloakAdmin.getUsers();
} catch (err) {
  const error = JSON.parse(err.message);
  // error.code: HTTP status code
  // error.message: Keycloak error message or fallback
  // error.stack: Detailed error stack
  if (error.code === 401) {
    // Handle unauthorized
  }
  console.error(error.code, error.message);
}
```

#### Error Codes

- `401`: Unauthorized (invalid credentials)
- `403`: Forbidden (insufficient permissions)
- `404`: Not found (invalid ID or resource)
- `409`: Conflict (duplicate resource)
- `500`: Internal server error or unknown error

#### Best Practices

- Always parse the error with `JSON.parse(err.message)`
- Log or display `error.code` and `error.message` for debugging
- Use error codes to handle specific cases in your app

## TypeScript & IntelliSense

Type declarations are included for all entities and methods. You get auto-complete and suggestions in your IDE when using this package. All input objects (user, client, options) are fully typed for safety and developer experience.

## License

ISC
