const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')
// or require('secp256k1/elliptic')
//   if you want to use pure js implementation in node

// generate message to sign
// message should have 32-byte length, if you have some other length you can hash message
// for example `msg = sha256(rawMessage)`

// const msg = randomBytes(32)
const msg = new Uint8Array([
  0xde,0x5b,0x9e,0xb9,0xe7,0xc5,0x59,0x29,0x30,0xeb,0x2e,0x30,0xa0,0x13,0x69,0xc3,
  0x65,0x86,0xd8,0x72,0x08,0x2e,0xd8,0x18,0x1e,0xe8,0x3d,0x2a,0x0e,0xc2,0x0f,0x04
])
const msgAsBuffer = Buffer.from(msg)
console.log("msg              ", msgAsBuffer.toString('hex'))

// const privKey = randomBytes(32)
const privKey = new Uint8Array([
  0x51,0x0f,0x96,0xa8,0xef,0xd0,0xb1,0x1e,0x21,0x17,0x33,0xc1,0xac,0x5e,0x3f,0xa6,
  0xf3,0xd3,0xfc,0xdd,0x62,0x86,0x9e,0x37,0x6c,0x47,0xde,0xcb,0x3e,0x14,0xfe,0xa1
])
const privKeyAsBuffer = Buffer.from(privKey)
console.log("privKey          ", privKeyAsBuffer.toString('hex'))
if (!secp256k1.privateKeyVerify(privKey)) {
  console.log("private key invalid")
  process.exit(-1)
}

// get the public key in a compressed format
const pubKey = secp256k1.publicKeyCreate(privKey)
const pubKeyAsBuffer = Buffer.from(pubKey)
console.log("pubKeyAsBuffer   ", pubKeyAsBuffer.toString('hex'))

// sign the message
const sigObj = secp256k1.ecdsaSign(msg, privKey)
const signatureAsBuffer = Buffer.from(sigObj.signature)
console.log("sigObj           ", signatureAsBuffer.toString('hex'), sigObj.recid)

// verify the signature
console.log("verify           ", secp256k1.ecdsaVerify(sigObj.signature, msg, pubKey))
// => true


const pub_key_recovered = secp256k1.ecdsaRecover(sigObj.signature, sigObj.recid, msg)
const pub_key_recovered_as_buffer = Buffer.from(pub_key_recovered)
console.log("pub_key_recovered", pub_key_recovered_as_buffer.toString('hex'))
console.log("match", pub_key_recovered_as_buffer.toString('hex') === pubKeyAsBuffer.toString('hex'))