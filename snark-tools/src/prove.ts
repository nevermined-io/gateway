
import { utils } from '@nevermined-io/nevermined-sdk-js'

const { makeKey, secretToPublic, makePublic, encryptKey, ecdh, prove, hashKey } = utils

async function main() {
    console.error(process.argv)
    let providerK = makeKey(process.argv[2])
    console.error(providerK)
    let providerPub = secretToPublic(providerK)
    let data = Buffer.from(process.argv[3].substr(2), 'hex')
    let buyerPub = makePublic(process.argv[4], process.argv[5])
    const cipher = encryptKey(data, ecdh(providerK, buyerPub))
    const proof = await prove(buyerPub, providerPub, providerK, data)
    const hash = hashKey(data)
    const res = { hash, cipher: [cipher.x, cipher.y], proof }
    console.log(JSON.stringify(res))
    process.exit(0)
}

main()
