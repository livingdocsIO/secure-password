# `secure-password`

[![Build Status](https://travis-ci.org/emilbayes/secure-password.svg?branch=master)](https://travis-ci.org/emilbayes/secure-password)
[![Build status](https://ci.appveyor.com/api/projects/status/a1atq7xypwf3ebfc/branch/master?svg=true)](https://ci.appveyor.com/project/emilbayes/secure-password/branch/master)

> Making Password storage safer for all

## Features

- State of the art password hashing algorithm (Argon2id)
- Safe defaults for most applications
- Future-proof so work factors and hashing algorithms can be easily upgraded
- `Buffers` everywhere for safer memory management

## Usage

```js
const securePassword = require('secure-password')

// Initialise our password policy
const pwd = securePassword()

const userPassword = Buffer.from('my secret password')

async function run () {
  // Register user
  const hash = await pwd.hash(userPassword)

  // Save hash somewhere
  const result = await pwd.verify(userPassword, hash)

  switch (result) {
    case securePassword.INVALID_UNRECOGNIZED_HASH:
      return console.error('This hash was not made with secure-password. Attempt legacy algorithm')
    case securePassword.INVALID:
      return console.log('Invalid password')
    case securePassword.VALID:
      return console.log('Authenticated')
    case securePassword.VALID_NEEDS_REHASH:
      console.log('Yay you made it, wait for us to improve your safety')

      try {
        const improvedHash = await pwd.hash(userPassword)
        // Save improvedHash somewhere
      } catch (err)
        console.error('You are authenticated, but we could not improve your safety this time around')
      }
      break
  }
}

run()
```

## API

### `const pwd = new SecurePassword(opts)`

Make a new instance of `SecurePassword` which will contain your settings. You
can view this as a password policy for your application. `opts` takes the
following keys:

```js
// Initialise our password policy (these are the defaults)
const pwd = securePassword({
  memoryCost: securePassword.defaults.memoryCost,
  timeCost: securePassword.defaults.timeCost
})
```

They're both constrained by the constants `SecurePassword.limits.memoryCost.min` -
 `SecurePassword.limits.memoryCost.max` and
`SecurePassword.limits.timeCost.min` - `SecurePassword.limits.timeCost.max`. If not provided
they will be given the default values `SecurePassword.defaults.memoryCost` and
`SecurePassword.defaults.timeCost` which should be fast enough for a general
purpose web server without your users noticing too much of a load time. However
your should set these as high as possible to make any kind of cracking as costly
as possible. A load time of 1s seems reasonable for login, so test various
settings in your production environment.

The settings can be easily increased at a later time as hardware most likely
improves (Moore's law) and adversaries therefore get more powerful. If a hash is
attempted verified with weaker parameters than your current settings, you get a
special return code signalling that you need to rehash the plaintext password
according to the updated policy. In contrast to other modules, this module will
not increase these settings automatically as this can have ill effects on
services that are not carefully monitored.

### `const hash = await pwd.hash(password)`

Takes Buffer `password` and hashes it. The hashing is done on the same thread as
the event loop, therefore normal execution and I/O will be blocked.
The function may `throw` a potential error, but most likely return
the Buffer `hash`.

`password` must be a Buffer of length `SecurePassword.defaults.passwordLength.min` - `SecurePassword.defaults.passwordLength.max`.  
`hash` will be a Buffer any length based on the config parameters.

### `const symbol = await pwd.verify(password, hash)`

Takes Buffer `password` and hashes it and then safely compares it to the
Buffer `hash`. The hashing is done by a seperate worker as to not block the
event loop, so normal execution and I/O can continue.
The promise is rejected with potential error, or resolved with one of the symbols
`SecurePassword.INVALID`, `SecurePassword.VALID`, `SecurePassword.VALID_NEEDS_REHASH` or `SecurePassword.INVALID_UNRECOGNIZED_HASH`.
Check with strict equality for one the cases as in the example above.

If `enum === SecurePassword.VALID_NEEDS_REHASH` you should call `pwd.hash` with
`password` and save the new `hash` for next time. Be careful not to introduce a
bug where a user trying to login multiple times, successfully, in quick succession
makes your server do unnecessary work.

`password` must be a Buffer of length `SecurePassword.defaults.passwordLength.min` - `SecurePassword.defaults.passwordLength.max`.  
`hash` will be a Buffer any length based on the config parameters.

### `SecurePassword.VALID`

The password was verified and is valid

### `SecurePassword.INVALID`

The password was invalid

### `SecurePassword.VALID_NEEDS_REHASH`

The password was verified and is valid, but needs to be rehashed with new
parameters

### `SecurePassword.INVALID_UNRECOGNIZED_HASH`

The hash was unrecognized and therefore could not be verified.
As an implementation detail it is currently very cheap to attempt verifying
unrecognized hashes, since this only requires some lightweight pattern matching.

### `SecurePassword.defaults`

```js
{
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 1,
  type: 2,
  version: 19
}
```
### `SecurePassword.limits`

```js
{
  hashLength: { max: 4294967295, min: 4 },
  memoryCost: { max: 4294967295, min: 2048 },
  timeCost: { max: 4294967295, min: 2 },
  parallelism: { max: 16777215, min: 1 },
  passwordLength: { min: 0, max: 4294967295 }
}
```

## Install

```sh
npm install secure-password
```

## Credits

I want to thank [Tom Streller](https://github.com/scan) for donating the package
name on npm. The `<1.0.0` versions that he had written and published to npm can
still be downloaded and the source is available in his [`scan/secure-password` repository](https://github.com/scan/secure-password)

## License

[ISC](LICENSE.md)
