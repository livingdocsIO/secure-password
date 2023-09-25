const {randomBytes, timingSafeEqual} = require('crypto')
const {promisify} = require('util')
const preGyp = require('@mapbox/node-pre-gyp')
const bindings = require(preGyp.find(require.resolve('argon2/package.json')))
const bindingsHash = promisify(bindings.hash)
const generateSalt = promisify(randomBytes)

const VERSION = 0x13

const types = Object.freeze({
  '0': 0,
  '1': 1,
  '2': 2,
  argon2d: 0,
  argon2i: 1,
  argon2id: 2
})

const names = Object.freeze({
  [types.argon2d]: 'argon2d',
  [types.argon2i]: 'argon2i',
  [types.argon2id]: 'argon2id',
})

const limits = Object.freeze({
  hashLength: { max: 4294967295, min: 4 },
  memoryCost: { max: 4294967295, min: 2048 },
  timeCost: { max: 4294967295, min: 2 },
  parallelism: { max: 16777215, min: 1 },
  passwordLength: { min: 0, max: 4294967295 }
})

// Attention, the old secure-password had different options
// timeCost=2, hashLength=32, memoryCost=65536
// memoryCost is now also in kilobytes instead of bytes
const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 1,
  type: types.argon2id,
  version: VERSION
})

const VALID = Symbol('VALID')
const INVALID = Symbol('INVALID')
const VALID_NEEDS_REHASH = Symbol('VALID_NEEDS_REHASH')
const INVALID_UNRECOGNIZED_HASH = Symbol('INVALID_UNRECOGNIZED_HASH')

securePassword.limits = limits
securePassword.defaults = defaults
securePassword.INVALID_UNRECOGNIZED_HASH = INVALID_UNRECOGNIZED_HASH
securePassword.INVALID = INVALID
securePassword.VALID = VALID
securePassword.VALID_NEEDS_REHASH = VALID_NEEDS_REHASH
securePassword.securePassword = securePassword

class AssertionError extends Error {}
AssertionError.prototype.name = 'AssertionError'

function assert (t, m) {
  if (t) return
  const err = new AssertionError(m)
  Error.captureStackTrace(err, assert)
  throw err
}

function assertBetween (value, {min, max}, key) {
  if (value >= min && value <= max) return
  const err = new AssertionError(`${key} (${value}), must be between ${min} and ${max}`)
  Error.captureStackTrace(err, assertBetween)
  throw err
}

const {serialize, deserialize: _phcDeserialize} = require('@phc/format')
// Removes trailing null bytes from a buffer and deserializes it
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
  return types[deserializedHash.id] !== undefined
}

async function argon2Verify (deserializedHash, passwordBuf, options) {
  const {id, version = 0x10, params: {m, t, p}, salt, hash} = deserializedHash

  return timingSafeEqual(await bindingsHash(passwordBuf, salt, {
    ...options,
    type: types[id],
    version: +version,
    hashLength: hash.length,
    memoryCost: +m,
    timeCost: +t,
    parallelism: +p
  }), hash)
}

function securePassword (opts = {}) {
  const options = Object.freeze({...defaults, ...opts})
  const type = opts.type !== undefined ? types[opts.type] : defaults.type
  assert(type, 'Invalid type, must be one of argon2d, argon2i or argon2id')

  const serializeOpts = Object.freeze({
    id: names[type],
    version: VERSION,
    params: {
      m: options.memoryCost,
      t: options.timeCost,
      p: options.parallelism
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

module.exports = securePassword
