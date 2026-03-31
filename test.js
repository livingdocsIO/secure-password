const {test} = require('node:test')
const assert = require('node:assert/strict')
const {securePassword, defaults} = require('./index.js')

const messages = {
  [securePassword.VALID]: 'valid',
  [securePassword.INVALID]: 'invalid',
  [securePassword.VALID_NEEDS_REHASH]: 'valid needs rehash',
  [securePassword.INVALID_UNRECOGNIZED_HASH]: 'invalid unrecognized hash'
}

function verifyStatus (name, expected, actual) {
  assert.equal(actual, expected, `'${name}' expected to be ${messages[expected]}, but was ${messages[actual]}`)
}

test('Can hash password', async function () {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secrets')
  const passwordHash = await pwd.hash(userPassword)
  assert.ok(!userPassword.equals(passwordHash))
})

test('Can hash password simultaneous', async function () {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secrets')
  const [hash1, hash2] = await Promise.all([pwd.hash(userPassword), pwd.hash(userPassword)])

  assert.ok(!userPassword.equals(hash1))
  assert.ok(!userPassword.equals(hash2))
})

test('Can verify password', async function () {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secret')
  const passwordHash = await pwd.hash(userPassword)
  const bool = await pwd.verify(userPassword, passwordHash)
  assert.equal(bool, securePassword.VALID)
})

test('Needs rehash async', async function () {
  const weakPwd = securePassword({
    memoryCost: defaults.memoryCost,
    timeCost: defaults.timeCost
  })

  const betterPwd = securePassword({
    memoryCost: defaults.memoryCost + 1024,
    timeCost: defaults.timeCost + 1
  })

  const userPassword = Buffer.from('my secret')
  const wrongPassword = Buffer.from('my secret 2')
  const pass = Buffer.from('hello world')
  const empty = Buffer.from('')
  const argon2ipass = Buffer.from('$argon2i$v=19$m=32768,t=4,p=1$bpvGgU64uCxxNQvif+wfwA$wqyV/Q/Z/Th8U5IZxAA7DVb2U1kKHm5TxK9a6AYd9IU')
  const argon2ipassempty = Buffer.from('$argon2i$v=19$m=32768,t=4,p=1$7wYWA/n0GB4ikypIcyQXzQ$Bn7zNskqm7icpTcc4izX/qkIb5FABvU4l61EBi5miaY')

  const weakHash = await weakPwd.hash(userPassword)
  const weakValid = await weakPwd.verify(userPassword, weakHash)
  verifyStatus('weak valid', securePassword.VALID, weakValid)

  const weakInvalid = await weakPwd.verify(wrongPassword, weakHash)
  verifyStatus('weak invalid', securePassword.INVALID, weakInvalid)

  const rehashValid = await betterPwd.verify(userPassword, weakHash)
  verifyStatus('weak right', securePassword.VALID_NEEDS_REHASH, rehashValid)

  const rehashValidAlgo = await weakPwd.verify(pass, argon2ipass)
  verifyStatus('weak argon2idpass right', securePassword.VALID_NEEDS_REHASH, rehashValidAlgo)

  const weakNotRight = await weakPwd.verify(empty, argon2ipassempty)
  verifyStatus('weak argon2ipassempty right', securePassword.VALID_NEEDS_REHASH, weakNotRight)

  const betterHash = await betterPwd.hash(userPassword)

  const betterValid = await betterPwd.verify(userPassword, betterHash)
  verifyStatus('better valid', securePassword.VALID, betterValid)

  const betterInvalid = await betterPwd.verify(wrongPassword, betterHash)
  verifyStatus('better invalid', securePassword.INVALID, betterInvalid)
})

test('Can handle invalid hash sync', async function () {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(128)

  const unrecognizedHash = await pwd.verify(userPassword, invalidHash)
  verifyStatus('unrecognized hash', securePassword.INVALID_UNRECOGNIZED_HASH, unrecognizedHash)
})
