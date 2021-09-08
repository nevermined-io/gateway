
import { utils } from '@nevermined-io/nevermined-sdk-js'

function main() {
    let data = Buffer.from(process.argv[2].substr(2), 'hex')
    let hash = utils.hashKey(data)
    console.log('HASH', hash)
}

main()
