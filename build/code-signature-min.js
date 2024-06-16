#!/usr/bin/env -S bun run
// SPDX-License-Identifier: CC-BY-4.0
// This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
// To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/
// Author: Andreas Timm
// Repository: https://github.com/andreas-timm/code-signature-ts
// Version: 0.1.0
// @eip191signature 0x0b41ef7d985d20eec09246874f286c8702d8809fd0dc2dcf925a089d77e17b5b7d29d2945008d228fe19e6b5947bb95cbd9341e62c806e0271dbb67a3628bc761c
// @sha256sum 0x9edeef886b97a91f6ecc661feb6d34bc4ad5183aac1ff1a938795483be96b4e9
import{sha256} from"viem";import{english,generateMnemonic,mnemonicToAccount} from"viem/accounts";async function run(){const filePath=process.argv[2]??process.argv[1];const content=await Bun.file(filePath).text();const keys=["eip191signature","sha256sum"];const contentOrig=keys.reduce((acc,k)=>acc.replace(new RegExp(`// @${k} \\S+\n`),""),content);let mnemonic=process.env.MNEMONIC;if(!mnemonic){mnemonic=generateMnemonic(english,256);console.log(mnemonic)}const signature=await mnemonicToAccount(mnemonic).signMessage({message:contentOrig});let updatedContent=content.replace(new RegExp(`// @${keys[0]} \\S+`),`// @${keys[0]} ${signature}`);let updatedData={eip191signature:signature,sha256sum:sha256(new TextEncoder().encode(updatedContent.replace(new RegExp(`// @${keys[1]} \\S+\n`),"")))};updatedContent=updatedContent.replace(new RegExp(`// @${keys[1]} \\S+`),`// @${keys[1]} ${updatedData.sha256sum}`);const match=content.match(new RegExp(`@(${keys.join("|")}) (\\S+)`,"g"));if(match){const data=Object.fromEntries(match.splice(0,2).map((item)=>item.slice(1).split(" ")));const success=keys.reduce((acc,k)=>{if(data[k]!==updatedData[k]){console.log(`// @${k} ${updatedData[k]}`);acc=false}return acc},true);if(success){console.log("OK");return}await Bun.write(filePath,updatedContent)}}import.meta.main&&run().then();export{run}
