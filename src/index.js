import jwt from 'jsonwebtoken';
import { UnauthorizedError, ForbiddenError } from '@yahapi/errors';
import _ from 'lodash';

/**
 * Checks whether a request scope matches `allowedScope` or wether request scope
 * contains a scope higher in hierarchy.
 */
export function checkScope(requestScope, allowedScope) {
  // If request scope matches allowed scope identically we're done
  if (requestScope === allowedScope) {
    return true;
  }

  // Check if requestScope is a scope higher in hierarchy
  const pieces = allowedScope.split(':');
  let tmpString = '';
  for (let i = 0; i < pieces.length; i++) {
    if (tmpString.length > 0) {
      tmpString += ':';
    }
    tmpString += pieces[i];
    if (requestScope === tmpString) {
      return true;
    }
  }

  // If we got this far requestScope does not contain allowedScope.
  return false;
}

/**
 * Grabs the bearer token from the request header and checks whether it contains
 * one of allowed scopes.
 */
export function validateScopes(req, ...allowedScopes) {
  if (!req.get('Authorization') || !req.get('Authorization').startsWith('Bearer ')) {
    throw new UnauthorizedError('invalid_token', 'No bearer token set');
  }

  // Extract token from Authorization header
  const token = req.get('Authorization').substring(7);
  if (token.length === 0) {
    throw new UnauthorizedError('invalid_token', 'No bearer token set');
  }

  // Decode JWT payload
  const payload = jwt.decode(token);
  if (!payload) {
    throw new UnauthorizedError('invalid_token', 'JWT is malformed');
  }

  // Scope might be missing in the token (scopes are an optional JWT property).
  // If scopes exist in token split scope by spaces.
  let scopes = [];
  if (payload.scope) {
    scopes = payload.scope.split(' ');
  }

  // Determine whether at least one request scope matches at least one of allowed scopes.
  const sufficientScope = _.some(scopes, (requestScope) => {
    return _.some(allowedScopes, (allowedScope) => {
      return checkScope(requestScope, allowedScope);
    });
  });
  if (!sufficientScope) {
    throw new ForbiddenError('insufficient_scope', 'Access token has insufficient privileges');
  }
}
