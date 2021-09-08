
import { utils } from '@nevermined-io/nevermined-sdk-js'

function main() {
    let key = utils.makeKey(process.argv[2])
    let publicKey = utils.secretToPublic(key)
    console.log('PRIVATE', key)
    console.log('PUBLIC', publicKey.x, publicKey.y)
}

main()
