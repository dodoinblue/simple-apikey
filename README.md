# Simple ApiKey

A small util to generate and authenticate API secret, using `aes-256-cbc`.

The generated secrets contain three parts:

* Master secret identifier: This identifies which master secret to be used to decode the secret. This allows smooth swapping of the master secret. The identifier is a YYYY-MM-DD string, so master secret cannot be updated twice in a day.

* Api key: The ID of the API key. Only keys in the validKeys list will be authenticated. This allows api key revocation.

* Free text: this part can carry any information, such as userId, etc.

## Usage

```javascript
// Encode
const gen = new ApiKeyGenerator(masterSecret);
const orgId = 'dummy+/name-=(*xyz';
const result = gen.createApiKey(orgId);

// result = {
//   orgId: 'dummy+/name-=(*xyz',
//   issuedAt: '2022-01-28T00:00:00.000Z',
//   apiKey: 'H/Tpb4sWjiijSCMyknqH6A==',
//   apiSecret: 'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg=='
// }

// Decode
const verifier = new ApiKeyVerifier(
  masterSecret,
  ['H/Tpb4sWjiijSCMyknqH6A=='], // validApiKeys
  '2022-04-11', // Optional: masterSecretPublishedDate
  previousMasterSecret // Optional: previous master key
);
const apiSecret =
  'MjAyMi0wMS0yOB/06W+LFo4oo0gjMpJ6h+hAqCqb2LMTeN6VUbGbz7+ZT5PTeB2xiCNqiMUepuepLg==';
const verifiedResult = verifier.validateApiSecret(apiSecret);
// verifiedResult = 'dummy+/name-=(*xyz'
```