// electron-builder's mac.sign hook for the self-signed certificate (electron-builder.cjs).
//
// electron-builder only signs with identities that `security find-identity -v` lists, which leaves out
// a self-signed certificate: it is not trusted, and codesign does not need it to be. So the config keeps
// identity '-' (ad-hoc), which makes electron-builder build every signing option as usual, and this
// hook swaps in our certificate (by SHA-1, ONSCREENLY_MAC_SIGN_IDENTITY) and keychain before signing.
// Every binary inside the app is signed with it, so macOS sees one stable identity from build to build
// and keeps the user's permissions across updates.
const { signAsync } = require('@electron/osx-sign');

/**
 * @param {import('@electron/osx-sign').SignOptions} opts what electron-builder would sign with
 * @param {{ signAsync?: typeof signAsync, env?: NodeJS.ProcessEnv }} [deps] for tests
 */
module.exports = async function macSelfSign(opts, _packager, deps = {}) {
  const env = deps.env || process.env;
  const identity = String(env.ONSCREENLY_MAC_SIGN_IDENTITY || '').trim();
  if (!/^[0-9A-F]{40}$/i.test(identity)) {
    throw new Error('ONSCREENLY_MAC_SIGN_IDENTITY must be the SHA-1 of the signing certificate.');
  }
  const keychain = env.ONSCREENLY_MAC_SIGN_KEYCHAIN || opts.keychain || undefined;
  await (deps.signAsync || signAsync)({
    ...opts,
    identity,
    // Not trusted by macOS, so `find-identity -v` would reject it; codesign signs with it regardless.
    identityValidation: false,
    keychain
  });
};
