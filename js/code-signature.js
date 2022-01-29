#!/usr/bin/env node
// SPDX-License-Identifier: CC0-1.0
// @sha256sum 0x26ecafc51db8d22fb4edb498d4deef16c9ed1d3ee3da19851f13b97c1d90d4e4
// @eip191signature 0x6ff3f49222a91cb1ab60198a7e132b0fe77b5e51f5c442594143246164e1615b7e0e50a64576a1685901950dd39286c32f6ebde3b7eff42f34fa29767cb121661b

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
            console.log('sha256sum check: ', result.sha256SumPassed ? 'OK' : 'FAIL')
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

const forceUpdateOrigFile = (content, signature, sha256sum, verifyData, options) => {
    let isChanged = false

    if (verifyData.woSha256Sum.value !== sha256sum) {
        content = getFilteredContent(content, '@sha256sum', sha256sum).content
        isChanged = true
    }

    if (verifyData.toSign.value !== signature) {
        content = getFilteredContent(content, '@eip191signature', signature).content
        isChanged = true
    }

    if (isChanged) {
        return writeFile(options.filePath, content).then(() => {
            if (options.silent !== true) {
                console.log('---')
                console.log(`File "${options.filePath}" is written.`)
            }
            return {signature, sha256sum, verifyData}
        })
    } else {
        if (options.silent !== true) {
            console.log('---')
            console.log(`File "${options.filePath}" is not changed.`)
        }
    }

    return {signature, sha256sum, verifyData}
}

const signFile = (options) => readFile(options.filePath, 'utf8').then(content => {
    const verifyData = verifyCurrent(content, options)
    if (options.onlyCheck === true) {
        if (options.silent !== true && verifyData.woSha256Sum.value === null && verifyData.toSign.value === null) {
            console.log('Signature not found.')
        }
        return Promise.resolve()
    }

    const mnemonicResolver = process.env.MNEMONIC ? Promise.resolve(process.env.MNEMONIC) : readMnemonic()
    return mnemonicResolver
        .then(mnemonic => signMessage(verifyData.toSign.content, mnemonic).then(data => {
            const toSha256Sum = verifyData.toSign.value === null ? verifyData.toSign : getFilteredContent(
                verifyData.woSha256Sum.content,
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
                return forceUpdateOrigFile(content, data.signature, sha256sum, verifyData, options)
            }

            return {signature: data.signature, sha256sum, verifyData}
        }))
})

if (require.main === module) {
    const options = process.argv.slice(2).reduce((acc, item) => {
        if (item === '-v') {acc.onlyCheck = true}
        else if (item === '-f') {acc.force = true}
        else if (item === '-s') {acc.silent = true}
        else {acc.filePath = item}
        return acc
    }, {})

    if (options.filePath === undefined) {
        console.log('Usage: code-signature [-v — only verify] [-f — force set] [-s — silent] <FILE>')
    } else {
        signFile(options).catch(console.error)
    }
} else {
    module.exports = {signFile}
}
