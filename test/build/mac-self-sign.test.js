const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const macSelfSign = require('../../scripts/mac-self-sign');
const HASH = 'A1B2C3D4E5F60718293A4B5C6D7E8F9001122334';

function freshConfig(env) {
  const original = { ...process.env };
  try {
    for (const k of [
      'MAC_SIGN',
      'ONSCREENLY_MAC_SIGN_IDENTITY',
      'APPLE_ID',
      'APPLE_APP_SPECIFIC_PASSWORD',
      'APPLE_TEAM_ID'
    ])
      delete process.env[k];
    Object.assign(process.env, env);
    delete require.cache[require.resolve('../../electron-builder.cjs')];
    return require('../../electron-builder.cjs');
  } finally {
    process.env = original;
    delete require.cache[require.resolve('../../electron-builder.cjs')];
  }
}

test('the self-signed build keeps the ad-hoc setup and signs through the hook; a Developer ID wins', () => {
  const adHoc = freshConfig({});
  assert.equal(adHoc.mac.sign, undefined);
  assert.equal(adHoc.mac.identity, '-');

  const selfSigned = freshConfig({ ONSCREENLY_MAC_SIGN_IDENTITY: HASH });
  assert.equal(selfSigned.mac.identity, '-');
  assert.equal(selfSigned.mac.sign, 'scripts/mac-self-sign.js');
  assert.equal(selfSigned.mac.hardenedRuntime, false);
  assert.equal(selfSigned.mac.notarize, false);
  assert.ok(require('node:fs').existsSync(path.join(ROOT, selfSigned.mac.sign)));

  const developerId = freshConfig({ MAC_SIGN: '1', ONSCREENLY_MAC_SIGN_IDENTITY: HASH });
  assert.equal(developerId.mac.sign, undefined);
  assert.equal(developerId.mac.identity, undefined);
});

test('the hook signs everything electron-builder prepared, with our certificate and keychain', async () => {
  let signed;
  const prepared = {
    app: '/tmp/Onscreenly.app',
    identity: '-',
    identityValidation: false,
    platform: 'darwin',
    optionsForFile: () => ({ hardenedRuntime: false }),
    keychain: undefined
  };
  await macSelfSign(prepared, null, {
    env: { ONSCREENLY_MAC_SIGN_IDENTITY: HASH, ONSCREENLY_MAC_SIGN_KEYCHAIN: '/tmp/signing.keychain-db' },
    signAsync: async (opts) => {
      signed = opts;
    }
  });
  assert.equal(signed.identity, HASH);
  assert.equal(signed.identityValidation, false);
  assert.equal(signed.keychain, '/tmp/signing.keychain-db');
  assert.equal(signed.app, prepared.app);
  assert.equal(signed.optionsForFile, prepared.optionsForFile);
});

test('the hook refuses anything that is not a certificate fingerprint', async () => {
  for (const identity of ['', '-', 'Onscreenly Self-Signed', 'A1B2', `${HASH} --deep`]) {
    await assert.rejects(
      macSelfSign({ app: '/tmp/Onscreenly.app' }, null, {
        env: { ONSCREENLY_MAC_SIGN_IDENTITY: identity },
        signAsync: async () => assert.fail('must not sign')
      }),
      /SHA-1/
    );
  }
});
