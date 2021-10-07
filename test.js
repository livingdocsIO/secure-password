const test = require('tape')
const securePassword = require('./index.js')

const messages = {
  [securePassword.VALID]: 'valid',
  [securePassword.INVALID]: 'invalid',
  [securePassword.VALID_NEEDS_REHASH]: 'valid needs rehash',
  [securePassword.INVALID_UNRECOGNIZED_HASH]: 'invalid unrecognized hash'
}

function verifyStatus (assert, name, expected, actual) {
  if (expected === actual) return assert.ok(true, `'${name}' is ${messages[expected]}`)
  assert.ok(false, `'${name}' expected to be ${messages[expected]}, but was ${messages[actual]}`)
}

test('Can hash password', async function (assert) {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secrets')
  const passwordHash = await pwd.hash(userPassword)
  assert.notOk(userPassword.equals(passwordHash))
  assert.end()
})

test('Can hash password simultaneous', async function (assert) {
  assert.plan(2)
  const pwd = securePassword()
  const userPassword = Buffer.from('my secrets')
  const [hash1, hash2] = await Promise.all([pwd.hash(userPassword), pwd.hash(userPassword)])

  assert.notOk(userPassword.equals(hash1))
  assert.notOk(userPassword.equals(hash2))
})

test('Can verify password (identity) using promises', async function (assert) {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secret')
  const passwordHash = await pwd.hash(userPassword)
  const bool = await pwd.verify(userPassword, passwordHash)
  assert.ok(bool === securePassword.VALID)
  assert.end()
})

test('Needs rehash async', async function (assert) {
  assert.plan(7)
  const weakPwd = securePassword({
    memoryCost: securePassword.MEMLIMIT_DEFAULT,
    timeCost: securePassword.OPSLIMIT_DEFAULT
  })

  const betterPwd = securePassword({
    memoryCost: securePassword.MEMLIMIT_DEFAULT + 1024,
    timeCost: securePassword.OPSLIMIT_DEFAULT + 1
  })

  const userPassword = Buffer.from('my secret')
  const wrongPassword = Buffer.from('my secret 2')
  const pass = Buffer.from('hello world')
  const empty = Buffer.from('')
  const argon2ipass = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkYnB2R2dVNjR1Q3h4TlF2aWYrd2Z3QSR3cXlWL1EvWi9UaDhVNUlaeEFBN0RWYjJVMWtLSG01VHhLOWE2QVlkOUlVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')
  const argon2ipassempty = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkN3dZV0EvbjBHQjRpa3lwSWN5UVh6USRCbjd6TnNrcW03aWNwVGNjNGl6WC9xa0liNUZBQnZVNGw2MUVCaTVtaWFZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')

  const weakHash = await weakPwd.hash(userPassword)
  const weakValid = await weakPwd.verify(userPassword, weakHash)
  verifyStatus(assert, 'weak valid', securePassword.VALID, weakValid)

  const weakInvalid = await weakPwd.verify(wrongPassword, weakHash)
  verifyStatus(assert, 'weak invalid', securePassword.INVALID, weakInvalid)

  const rehashValid = await betterPwd.verify(userPassword, weakHash)
  verifyStatus(assert, 'weak right', securePassword.VALID_NEEDS_REHASH, rehashValid)

  const rehashValidAlgo = await weakPwd.verify(pass, argon2ipass)
  verifyStatus(assert, 'weak argon2idpass right', securePassword.VALID_NEEDS_REHASH, rehashValidAlgo)

  const weakNotRight = await weakPwd.verify(empty, argon2ipassempty)
  verifyStatus(assert, 'weak argon2ipassempty right', securePassword.VALID_NEEDS_REHASH, weakNotRight)

  const betterHash = await betterPwd.hash(userPassword)

  const betterValid = await betterPwd.verify(userPassword, betterHash)
  verifyStatus(assert, 'better valid', securePassword.VALID, betterValid)

  const betterInvalid = await betterPwd.verify(wrongPassword, betterHash)
  verifyStatus(assert, 'better invalid', securePassword.INVALID, betterInvalid)
})

test('Can handle invalid hash sync', async function (assert) {
  const pwd = securePassword()
  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(securePassword.HASH_BYTES)

  const unrecognizedHash = await pwd.verify(userPassword, invalidHash)
  verifyStatus(assert, 'unrecognized hash', securePassword.INVALID_UNRECOGNIZED_HASH, unrecognizedHash)
  assert.end()
})
