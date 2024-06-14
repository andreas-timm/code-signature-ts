#!/usr/bin/env -S bun run
// @eip191signature 0xd3f262a8a7a0a8ad1f7455472b1124703814d39f7ae0cbb8e7559b55001545d1794eb040c80d70f8cea182afe60e0ac344277d4f002ac0a076f1f0c949b89a661b
// @sha256sum 0x53a500071858618c65b00f33e1c2f79a2463f2e6d1122b868d932d6971c957bd

import { sha256 } from 'viem'
import { english, generateMnemonic, mnemonicToAccount } from 'viem/accounts'

export async function run() {
    const filePath = process.argv[2] ?? process.argv[1]
    const content = await Bun.file(filePath).text()
    const keys = ['eip191signature', 'sha256sum'] as const
    const contentOrig = keys.reduce((acc, k) => acc.replace(new RegExp(`// @${k} \\S+\n`), ''), content)
    let mnemonic = process.env.MNEMONIC
    if (!mnemonic) {
        mnemonic = generateMnemonic(english, 256)
        console.log(mnemonic)
    }

    const signature = await mnemonicToAccount(mnemonic).signMessage({ message: contentOrig })
    let updatedContent = content.replace(new RegExp(`// @${keys[0]} \\S+`), `// @${keys[0]} ${signature}`)
    let updatedData = {
        eip191signature: signature,
        sha256sum: sha256(new TextEncoder().encode(updatedContent.replace(new RegExp(`// @${keys[1]} \\S+\n`), ''))),
    }
    updatedContent = updatedContent.replace(
        new RegExp(`// @${keys[1]} \\S+`),
        `// @${keys[1]} ${updatedData.sha256sum}`,
    )

    const match = content.match(new RegExp(`@(${keys.join('|')}) (\\S+)`, 'g'))
    if (match) {
        const data = Object.fromEntries((match as string[]).splice(0, 2).map((item) => item.slice(1).split(' ')))
        const success = keys.reduce((acc: boolean, k: (typeof keys)[number]) => {
            if (data[k] !== updatedData[k]) {
                console.log(`// @${k} ${updatedData[k]}`)
                acc = false
            }
            return acc
        }, true)
        if (success) {
            console.log('OK')
            return
        }
        await Bun.write(filePath, updatedContent)
    }
}

import.meta.main && run().then()
