import { test, expect } from 'bun:test'
import { entropyToMnemonic } from '@scure/bip39'
import { codeSignature } from '../src/code-signature.ts'
import { sha256 } from 'viem'
import { english, mnemonicToAccount } from 'viem/accounts'
import tmp from 'tmp'
import { unlinkSync } from 'node:fs'

test('main', async () => {
    const filePath = 'test/data/test-code.ts'

    const entropyText = 'test'
    const mnemonic = entropyToMnemonic(sha256(new TextEncoder().encode(entropyText), 'bytes'), english)
    const account = mnemonicToAccount(mnemonic)

    const tmpFileObj = tmp.fileSync()

    await codeSignature({ filePath, write: true, mnemonic, out: tmpFileObj.name, prefix: '//', silent: true })
    const signedContent = await Bun.file(tmpFileObj.name).text()

    expect(signedContent).toContain(`// @sha256sum 0x786045f7ccc832aa68563116823b53c9d4a0d2755b06badd38c9b41f7accb694`)
    expect(signedContent).toContain(
        [
            '// @sha256sum 0x786045f7ccc832aa68563116823b53c9d4a0d2755b06badd38c9b41f7accb694',
            '// @eip191signature 0xde9fec4e5fd25321eafc169b0c3e80d28e98adbbbfcfc4339a6995b90174ad197912f0552867f8d562c6c33b42eaac525c05acc1cd21161206d4734f1ac3f6821b',
        ].join('\n'),
    )

    const { verifyResult } = await codeSignature({ filePath: tmpFileObj.name, prefix: '//', verify: true })
    expect(verifyResult.address).toEqual(account.address)

    unlinkSync(tmpFileObj.name)
})
