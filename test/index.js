import jwt from 'jsonwebtoken';
import { expect } from 'chai';
import { checkScope, validateScopes } from '../src';

/**
 * Creates a request object stub with a signed JWT Authorization Bearer.
 */
function createRequest(scope) {
  const headers = new Map();
  headers.set('Authorization', 'Bearer ' + jwt.sign({ scope }, 'secret'));

  return {
    get: (header) => headers.get(header),
  };
}

describe('checkScope(requestScope, allowedScope)', () => {
  it('should match identical scopes', () => {
    expect(checkScope('user:emails:read', 'user:emails:read')).to.equal(true);
  });

  it('should match scope higher in hierarchy', () => {
    expect(checkScope('user:emails', 'user:emails:read')).to.equal(true);
  });

  it('should return false when scope is insufficient', () => {
    expect(checkScope('user:emails:read', 'user:emails')).to.equal(false);
  });
});

describe('validateScopes(req, ...allowedScopes)', () => {
  it('should pass hierarchical scopes', () => {
    validateScopes(createRequest('user:emails'), 'user:emails');
    validateScopes(createRequest('user'), 'user:emails');
  });

  it('should accept multiple allowedScopes', () => {
    validateScopes(createRequest('admin'), 'user:emails', 'admin');
  });

  it('should throw 403 "insufficient_scope" if request scope is insufficient', () => {
    try {
      validateScopes(createRequest('user:emails'), 'user', 'admin');
      expect(true).to.equal(false); // Intentionally fail, an error should have been thrown
    } catch (err) {
      expect(err.httpStatus).to.equal(403);
      expect(err.code).to.equal('insufficient_scope');
      expect(err.message).to.equal('Access token has insufficient privileges');
    }
  });

  it('should throw 401 "invalid_token" if request scope is missing', () => {
    const reqStub = {
      get: () => undefined,
    };
    try {
      validateScopes(reqStub, 'user', 'admin');
      expect(true).to.equal(false); // Intentionally fail, an error should have been thrown
    } catch (err) {
      expect(err.httpStatus).to.equal(401);
      expect(err.code).to.equal('invalid_token');
      expect(err.message).to.equal('No bearer token set');
    }
  });

  it('should throw 401 "invalid_token" if Bearer is missing in Authorization header', () => {
    const reqStub = {
      get: () => jwt.sign({ scope: 'no-bearer' }, 'secret'), // misses Bearer prefix
    };
    try {
      validateScopes(reqStub, 'user', 'admin');
      expect(true).to.equal(false); // Intentionally fail, an error should have been thrown
    } catch (err) {
      expect(err.httpStatus).to.equal(401);
      expect(err.code).to.equal('invalid_token');
      expect(err.message).to.equal('No bearer token set');
    }
  });

  it('should throw 401 "invalid_token" if JWT is malformed', () => {
    const reqStub = {
      get: () => 'Bearer malformedtoken', // misses Bearer prefix
    };
    try {
      validateScopes(reqStub, 'user', 'admin');
      expect(true).to.equal(false); // Intentionally fail, an error should have been thrown
    } catch (err) {
      expect(err.httpStatus).to.equal(401);
      expect(err.code).to.equal('invalid_token');
      expect(err.message).to.equal('JWT is malformed');
    }
  });
});
