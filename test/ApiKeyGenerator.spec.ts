import { ApiKeyGenerator, ApiKeyVerifier, AuthError } from '../src';

const masterSecret = 'xx3ulm0xUnH0JYmcYWeYMrNiMkvmaLF4bxpzqPUqrqU=';
// {
//   orgId: 'dummy+/name-=(*xyz',
//   issuedAt: '2022-01-28T00:00:00.000Z',
//   apiKey: 'H/Tpb4sWjiijSCMyknqH6A==',
//   apiSecret: 'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg=='
// }

describe('ApiKeyGenerator', () => {
  it('should throw if master secret not set', () => {
    expect(() => new ApiKeyGenerator('')).toThrow();
  });

  it('should create api key', () => {
    const orgId = 'dummy+/name-=(*xyz';
    const date = new Date('2022-01-28');
    jest.useFakeTimers().setSystemTime(date);
    const gen = new ApiKeyGenerator(masterSecret);
    const result = gen.createApiKey(orgId);

    expect(result.orgId).toEqual(orgId);
    expect(Buffer.from(result.apiKey, 'base64')).toHaveLength(16);
    expect(result.issuedAt).toEqual(date.toISOString());

    const secretBuffer = Buffer.from(result.apiSecret, 'base64');
    expect(secretBuffer.slice(0, 10).toString()).toEqual('2022-01-28');
    expect(secretBuffer.slice(10, 26).toString('base64')).toEqual(result.apiKey);

    const verifier = new ApiKeyVerifier(masterSecret, [result.apiKey]);
    const verifiedResult = verifier.validateApiSecret(result.apiSecret);
    expect(verifiedResult).toEqual(orgId);
  });
});

describe('ApiKeyVerifier', () => {
  const masterSecret2 = 'fkOCpJgKYTJNRlwbbROz4Ftzw6RFD7OuLX4uytUCb94=';

  it('should throw error if master secret is not set', () => {
    expect(() => new ApiKeyVerifier('')).toThrow();
  });

  it('should throw auth error if previous secret does not exist before the current published date', () => {
    const verifier = new ApiKeyVerifier(masterSecret2, [], '2022-04-11');
    const apiSecret =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    expect(() => verifier.validateApiSecret(apiSecret)).toThrowError(AuthError);
  });

  it('should use previous master secret for api keys issued before the publish date', () => {
    const verifier = new ApiKeyVerifier(
      masterSecret2,
      ['H/Tpb4sWjiijSCMyknqH6A=='],
      '2022-04-11',
      masterSecret
    );
    const apiSecret =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    const verifiedResult = verifier.validateApiSecret(apiSecret);
    expect(verifiedResult).toEqual('dummy+/name-=(*xyz');
  });

  it('should use current master secret for api keys issued after the publish date', () => {
    const verifier = new ApiKeyVerifier(
      masterSecret,
      ['H/Tpb4sWjiijSCMyknqH6A=='],
      '2022-01-28',
      masterSecret2
    );
    const apiSecret =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    const verifiedResult = verifier.validateApiSecret(apiSecret);
    expect(verifiedResult).toEqual('dummy+/name-=(*xyz');
  });

  it('should throw auth error if api key is not in the valid keys list', () => {
    const verifier = new ApiKeyVerifier(masterSecret, ['a_different_iv'], '2022-04-11');
    const apiSecret =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    expect(() => verifier.validateApiSecret(apiSecret)).toThrowError(AuthError);
  });

  it('should throw auth error if secret is wrong', () => {
    const verifier = new ApiKeyVerifier(masterSecret, ['H/Tpb4sWjiijSCMyknqH6A=='], '2022-04-11');
    const wrongSecret1 =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLw==';
    const wrongSecret2 =
      'MjAyMiwwMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    const wrongSecret3 =
      'MjAyMi0wMS0yOB/16W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    expect(() => verifier.validateApiSecret(wrongSecret1)).toThrowError(AuthError);
    expect(() => verifier.validateApiSecret(wrongSecret2)).toThrowError(AuthError);
    expect(() => verifier.validateApiSecret(wrongSecret3)).toThrowError(AuthError);

    const verifier2 = new ApiKeyVerifier(masterSecret2, ['H/Tpb4sWjiijSCMyknqH6A==']);
    const wrongSecret4 =
      'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
    expect(() => verifier2.validateApiSecret(wrongSecret4)).toThrowError(AuthError);
  });

  it('should throw error if coded date does not match with issued date', () => {
    const wrongSecret =
      'MjAyMi0wMS0yNx/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg=='; // one day earlier
    const verifier = new ApiKeyVerifier(masterSecret, ['H/Tpb4sWjiijSCMyknqH6A==']);
    expect(() => verifier.validateApiSecret(wrongSecret)).toThrowError(AuthError);
  });
});
