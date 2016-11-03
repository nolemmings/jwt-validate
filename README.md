# jwt-validate

This library contains JWT validation utility functions.

## Installation

```sh
npm install @nolemmings/jwt-validate
```

## Example

```js
import { validateScope } from '@nolemmings/jwt-validate';
import express from 'express';

const app = express();

app.get('/hello', (req, res) => {
  // Throws error if req.headers.Authorization does not contain valid jwt
  // or does not have scope 'hello:read' or 'hello'
  validateScope(req, 'hello:read');

  res.send('You have a valid request bearer');
});

app.listen(3000);
```

## validateScope(req, ...allowedScopes)

Checks if Authorization header has a JWT with a `scope` that matches at least one of `allowedScopes`. Throws an error if no match was found.

Scopes are interpreted as a hierarchical structure delimited by `:`. For example, `validateScope(req, 'user:email:read')` would succeed if JWT scope has one of the following scopes: `['user', 'user:email', 'user:email:read']`.

Example:

```js
import { validateScope } from '@nolemmings/jwt-validate';

// Checks if JWT scope contains either 'hello', 'hello:read' or 'admin'
validateScope(req, 'hello:read', 'admin');
```

When failed an error is thrown with the following format:

```js
{
  code: 'insufficient_scope',
  httpStatus: 403,
  message: 'Access token has insufficient privileges',
}
```

Other possible errors:

- `401 invalid_token` - when token is missing, malformed or invalid for other reasons.

Error codes are from [RFC 6750](https://tools.ietf.org/html/rfc6750).

## checkScope(requestScope, allowedScope)

Returns `true` if a single request scope matches `allowedScope` or if request scope contains a scope higher in hierarchy. Otherwise returns `false`.

For example:

```js
import { checkScope } from '@nolemmings/jwt-validate';

checkScope('user:email', 'user:email:read'); // Returns true
checkScope('user', 'user:email:read'); // Returns true
checkScope('user:email', 'user'); // Returns false
```
