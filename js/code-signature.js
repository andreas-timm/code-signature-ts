#!/usr/bin/env node
// SPDX-License-Identifier: CC0-1.0
// @sha256sum 0x6487a05aa4595197cbb005c73b6bcf5e565a97c2368168a6a43aa7cea42131a4
// @eip191signature 0xf27d28722870715db24ee48b0112440f8c66ee708616e2338934f67af21ec11b22f9bb0f96a162ce17a14ec41a2ab3ead073a443793b74a0dc1f19fc93ec48931b

const {readFile, writeFile} = require('fs/promises')
const ethers = require('ethers')
const readline = require('readline')


const readMnemonic = () => new Promise(resolve => {
    const rl = readline.createInterface({input: process.stdin, output: process.stdout})
    rl.stdoutMuted = true
    rl.question('Mnemonic: ', mnemonic => {
        process.stdout.write('\n')
        resolve(mnemonic)
        rl.close()
    })
    rl._writeToOutput = () => rl.output.write('*')
})

const signMessage = (message, mnemonic) => ethers.Wallet.fromMnemonic(mnemonic, "m/44'/60'/0'/0/0")
    .signMessage(message).then(signature => new Object({signature}))

const splitIndexLines = content => content.split(/([\r\n]+)/).reduce((acc, part, index) => {
    if (index % 2 === 0) {
        acc.push([part])
    } else {
        acc[acc.length - 1].push(part)
    }
    return acc
}, [])

const getFilteredContent = (content, key, replace) => {
    const lines = splitIndexLines(content)
    let filtered = []
    let value = null
    let index

    for (index = 0; index < lines.length; index++) {
        if (lines[index][0].match(new RegExp('^\\s*([*#;"]|//)?\\s*' + key))) {
            value = lines[index][0].match(new RegExp(`${key}\\s+(\\S+)`))[1]
            if (replace !== undefined) {
                filtered.push([
                    lines[index][0].replace(new RegExp(`(${key}\\s+)\\S+`), `\$1${replace}`),
                    lines[index][1]
                ].join(''))
            }
            filtered = filtered.concat(lines.splice(index + 1).map(line => line.join('')))
            break
        }

        filtered.push(lines[index].join(''))
    }

    return {content: filtered.join(''), value}
}

const verifyCurrent = (content, options) => {
    let result = {woSha256Sum: getFilteredContent(content, '@sha256sum')}

    if (result.woSha256Sum.value !== null) {
        const contentSha256sum = ethers.utils.sha256(ethers.utils.toUtf8Bytes(result.woSha256Sum.content))
        result.sha256SumPassed = result.woSha256Sum.value === contentSha256sum
        if (options.silent !== true) {
            console.log('sha256sum check:', result.sha256SumPassed ? 'OK' : 'FAIL')
        }
    }

    result.toSign = getFilteredContent(result.woSha256Sum.content, '@eip191signature')

    if (result.toSign.value !== null) {
        const signAddress = ethers.utils.verifyMessage(result.toSign.content, result.toSign.value)
        result.signAddress = signAddress
        if (options.silent !== true) {
            console.log('address:', signAddress)
        }
    }

    return result
}

const forceUpdateOrigFile = async (content, mnemonic, signature, sha256sum, result, options) => {
    let isChanged = false
    let changedContent

    if (result.woSha256Sum.value !== sha256sum) {
        changedContent = getFilteredContent(content, '@sha256sum', sha256sum).content
        if (changedContent === content) {
            const data = await signMessage(content, mnemonic)
            content = [`// @sha256sum ${sha256sum}`, content].join('\n')
            signature = data.signature
        } else {
            content = changedContent
        }
        isChanged = true
    }

    if (result.toSign.value !== signature) {
        changedContent = getFilteredContent(content, '@eip191signature', signature).content
        content = changedContent === content ? [`// @eip191signature ${signature}`, content].join('\n') : changedContent
        isChanged = true
    }

    if (isChanged) {
        return writeFile(options.filePath, content).then(() => {
            if (options.silent !== true) {
                console.log('---')
                console.log(`File "${options.filePath}" is written.`)
            }
            return {signature, sha256sum, result}
        })
    } else {
        if (options.silent !== true) {
            console.log('---')
            console.log(`File "${options.filePath}" is not changed.`)
        }
    }

    return {signature, sha256sum, result}
}

const signFile = (options) => readFile(options.filePath, 'utf8').then(content => {
    const result = verifyCurrent(content, options)

    if (result.sha256SumPassed === true) {
        return Promise.resolve({result})
    } else {
        if (options.onlyCheck === true) {
            if (options.silent !== true && result.woSha256Sum.value === null && result.toSign.value === null) {
                console.log('Signature not found.')
            }
            return Promise.resolve({result})
        }
    }

    const mnemonicResolver = process.env.MNEMONIC ? Promise.resolve(process.env.MNEMONIC) : readMnemonic()
    return mnemonicResolver
        .then(mnemonic => {
            if (!mnemonic) {
                const wallet = ethers.Wallet.createRandom()

                console.log('mnemonic: ', wallet.mnemonic)
                console.log('address: ', wallet.address)
                mnemonic = wallet.mnemonic.phrase
            }
            return signMessage(result.toSign.content, mnemonic).then(data => {
                const toSha256Sum = result.toSign.value === null ? result.toSign : getFilteredContent(
                    result.woSha256Sum.content,
                    '@eip191signature',
                    data.signature
                )
                const sha256sum = ethers.utils.sha256(ethers.utils.toUtf8Bytes(toSha256Sum.content))

                if (options.silent !== true) {
                    console.log('---')
                    console.log(`@sha256sum ${sha256sum}`)
                    console.log(`@eip191signature ${data.signature}`)
                }

                if (options.force === true) {
                    return forceUpdateOrigFile(content, mnemonic, data.signature, sha256sum, result, options)
                }

                return {signature: data.signature, sha256sum, result}
            })
        })
})

const printHelp = () => {
    console.log('Usage: code-signature [OPTIONS] <FILE>')
    console.log('OPTIONS:')
    console.log('  -v  only verify')
    console.log('  -f  force set')
    console.log('  -s  silent')
}

if (require.main === module) {
    const options = process.argv.slice(2).reduce((acc, item) => {
        if (item === '-h') {
            printHelp()
            process.exit(0)
        }
        else if (item === '-v') {acc.onlyCheck = true}
        else if (item === '-f') {acc.force = true}
        else if (item === '-s') {acc.silent = true}
        else {acc.filePath = item}
        return acc
    }, {})

    if (options.filePath === undefined) {
        printHelp()
    } else {
        signFile(options).catch(console.error)
    }
} else {
    module.exports = {signFile}
}
