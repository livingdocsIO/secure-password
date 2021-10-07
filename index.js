const argon2 = require('argon2')
const {randomBytes, timingSafeEqual} = require('crypto')
const {promisify} = require('util')
const preGyp = require('@mapbox/node-pre-gyp')
const bindings = require(preGyp.find(require.resolve('argon2/package.json')))
const bindingsHash = promisify(bindings.hash)
const generateSalt = promisify(randomBytes)

const limits = {
  ...bindings.limits,
  passwordLength: {min: 0, max: 4294967295}
}

const VALID = Symbol('VALID')
const INVALID = Symbol('INVALID')
const VALID_NEEDS_REHASH = Symbol('VALID_NEEDS_REHASH')
const INVALID_UNRECOGNIZED_HASH = Symbol('INVALID_UNRECOGNIZED_HASH')

SecurePassword.INVALID_UNRECOGNIZED_HASH = INVALID_UNRECOGNIZED_HASH
SecurePassword.INVALID = INVALID
SecurePassword.VALID = VALID
SecurePassword.VALID_NEEDS_REHASH = VALID_NEEDS_REHASH
SecurePassword.MEMLIMIT_DEFAULT = 1 << 12
SecurePassword.OPSLIMIT_DEFAULT = 3
SecurePassword.HASH_BYTES = 32

class AssertionError extends Error {}
AssertionError.prototype.name = 'AssertionError'

function assert (t, m) {
  if (t) return
  const err = new AssertionError(m)
  Error.captureStackTrace(err, assert)
  throw err
}

function assertBetween (value, {min, max}, key) {
  if (min <= value && value <= max) return
  const err = new AssertionError(
    `${key}, must be between ${limits.hashLength.min} and ${limits.hashLength.max}`
  )
  Error.captureStackTrace(err, assertBetween)
  throw err
}

const {serialize, deserialize: _phcDeserialize} = require('@phc/format')
function deserialize (hashBuf) {
  try {
    const i = hashBuf.indexOf(0x00)
    if (i !== -1) hashBuf = hashBuf.slice(0, i)
    return _phcDeserialize(hashBuf.toString())
  } catch (err) {
    return
  }
}

function needsRehash (deserializedHash, {version, memoryCost, timeCost}) {
  const {version: v, params: {m, t}} = deserializedHash
  return +v !== version || +m !== memoryCost || +t !== timeCost
}

function recognizedAlgorithm (deserializedHash) {
  if (!deserializedHash) return false
  return bindings.types[deserializedHash.id] !== undefined
}

async function argon2Verify (deserializedHash, passwordBuf, options) {
  const {id, version = 0x10, params: {m, t, p, data}, salt, hash} = deserializedHash

  return timingSafeEqual(await bindingsHash(passwordBuf, salt, {
    ...options,
    type: bindings.types[id],
    version: +version,
    hashLength: hash.length,
    memoryCost: +m,
    timeCost: +t,
    parallelism: +p,
    ...(data ? {associatedData: Buffer.from(data, 'base64')} : {})
  }), hash)
}

function SecurePassword (opts = {}) {
  const options = Object.freeze({
    hashLength: opts.hashLength || SecurePassword.HASH_BYTES,
    saltLength: opts.saltLength || 16,
    timeCost: opts.timeCost || opts.opslimit || SecurePassword.OPSLIMIT_DEFAULT,
    memoryCost: opts.memoryCost || opts.memlimit || SecurePassword.MEMLIMIT_DEFAULT,
    parallelism: opts.parallelism || 1,
    type: opts.type || bindings.types.argon2id,
    version: bindings.version
  })

  const serializeOpts = Object.freeze({
    id: bindings.names[options.type],
    version: bindings.version,
    params: {
      m: options.memoryCost,
      t: options.timeCost,
      p: options.parallelism
      // data: options.associatedData || undefined
    }
  })

  assertBetween(options.hashLength, limits.hashLength, 'Invalid options.hashLength')
  assertBetween(options.memoryCost, limits.memoryCost, 'Invalid options.memoryCost')
  assertBetween(options.timeCost, limits.timeCost, 'Invalid options.timeCost')
  assertBetween(options.parallelism, limits.parallelism, 'Invalid options.parallelism')

  async function hash (passwordBuf) {
    assert(passwordBuf instanceof Uint8Array, 'Invalid passwordBuf, must be Buffer or Uint8Array')
    assertBetween(passwordBuf.length, limits.passwordLength, 'Invalid passwordBuf length')

    const salt = await generateSalt(options.saltLength)
    const hash = await bindingsHash(passwordBuf, salt, options)
    return Buffer.from(serialize({
      id: serializeOpts.id,
      version: serializeOpts.version,
      params: serializeOpts.params,
      salt,
      hash
    }))
  }

  async function verify (passwordBuf, hashBuf) {
    assert(passwordBuf instanceof Uint8Array, 'Invalid passwordBuf, must be Buffer or Uint8Array')
    assert(hashBuf instanceof Uint8Array, 'Invalid hashBuf, must be Buffer or Uint8Array')
    assertBetween(passwordBuf.length, limits.passwordLength, 'Invalid passwordBuf')

    const deserializedHash = deserialize(hashBuf)
    if (recognizedAlgorithm(deserializedHash) === false) return INVALID_UNRECOGNIZED_HASH
    if (await argon2Verify(deserializedHash, passwordBuf, options) === false) return INVALID
    if (needsRehash(deserializedHash, options)) return VALID_NEEDS_REHASH
    return VALID
  }

  return {hash, verify}
}

module.exports = SecurePassword
