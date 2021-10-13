
import { utils } from '@nevermined-io/nevermined-sdk-js'

function split(a: Buffer) {
    const str = a.toString('hex')
    console.log(str, str.substr(0, 32), str.substr(32, 64))
    const left = BigInt('0x' + str.substr(0, 32))
    const right = BigInt('0x' + str.substr(32, 64))
    return [left, right]
}

function main() {
    let data = Buffer.from(process.argv[2].substr(2), 'hex')
    let hash = utils.hashKey(data)
    console.log(split(data), hash)
}

main()
