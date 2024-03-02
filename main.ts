// https://github.com/Eunovo/taproot-with-bitcoinjs
import {
    initEccLib,
    networks,
    script,
    Signer,
    payments,
    crypto,
    Psbt
} from "bitcoinjs-lib";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface } from 'ecpair';
import { Taptree } from "bitcoinjs-lib/src/types";
import varuint from "varuint-bitcoin";
const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');

initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
const network = networks.regtest;

function p2trPubkey(pubkey: Buffer): Buffer {
    return pubkey.subarray(1, 33)
}

async function taptree() {
    // bitcoin-cli -regtest sendtoaddress <script_address> 0.00010000
    // previous outpoint
    const prevHashStr = 'cc6bbc55755d2b3fc3a55bcb3fc9505804960a239abc0db9098c752aabd11003';
    const prevIndex = 1;
    const prevAmountSat = 10_000;

    // send address: bitcoin-cli -regtest getnewaddress "" bech32
    const sendAddrStr = 'bcrt1quqqccct6wqpq9tp7qqw0j74cy4wkmrc5mt3d3t';
    const feeSat = 330;

    //  <<signature>>
    //  <<preimage>>
    //
    //  OP_SHA256 <payment_hash> OP_EQUAL
    //  OP_IF
    //     <alicePubkey>
    //  OP_ELSE
    //     <bobPubkey>
    //  OP_ENDIF
    //  OP_CHKSIG
    //
    //  ↓↓
    //
    //  1)  OP_SHA256 <payment_hash> OP_EQUALVERIFY <alicePubkey> OP_CHKSIG
    //  2)  <bobPubkey> OP_CHECKSIG
    const preimage = Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex');
    const payment_hash = crypto.sha256(preimage);

    const keyAlice = ECPair.fromPrivateKey(Buffer.from('00112233445566778899aabbccddee0000112233445566778899aabbccddee00', 'hex'));
    const keyBob = ECPair.fromPrivateKey(Buffer.from('00112233445566778899aabbccddee0100112233445566778899aabbccddee01', 'hex'));


    const hash_script_asm = `OP_SHA256 ${payment_hash.toString('hex')} OP_EQUALVERIFY ${p2trPubkey(keyAlice.publicKey).toString('hex')} OP_CHECKSIG`;
    const hash_lock_script = script.fromASM(hash_script_asm);

    const p2pk_script_asm = `${p2trPubkey(keyBob.publicKey).toString('hex')} OP_CHECKSIG`;
    const p2pk_script = script.fromASM(p2pk_script_asm);

    const scriptTree: Taptree = [
        {
            output: hash_lock_script
        },
        {
            output: p2pk_script
        }
    ];
    console.log(`script1= ${hash_lock_script.toString('hex')}`);
    console.log(`script2= ${p2pk_script.toString('hex')}`);

    const script_p2tr = payments.p2tr({
        internalPubkey: p2trPubkey(keyBob.publicKey),
        scriptTree,
        network
    });
    const script_addr = script_p2tr.address ?? '';
    console.log(`send to this address: ${script_addr}`);
    console.log();

    const hash_lock_redeem = {
        output: hash_lock_script,
        redeemVersion: 0xc0,
    };
    const hash_lock_p2tr = payments.p2tr({
        internalPubkey: p2trPubkey(keyBob.publicKey),
        scriptTree,
        redeem: hash_lock_redeem,
        network,
    });

    const tapLeafScript = {
        leafVersion: hash_lock_redeem.redeemVersion,
        script: hash_lock_redeem.output,
        controlBlock: hash_lock_p2tr.witness![hash_lock_p2tr.witness!.length - 1],
    };

    const psbt = new Psbt({ network });
    psbt.addInput({
        hash: prevHashStr,
        index: prevIndex,
        witnessUtxo: {
            value: prevAmountSat,
            script: hash_lock_p2tr.output!,
        },
        tapLeafScript: [
            tapLeafScript,
        ],
    });
    const txinIndex = 0;

    psbt.addOutput({
        address: sendAddrStr,
        value: prevAmountSat - feeSat,
    });

    const scriptIdx = 0;
    const customFinalizer = (_inputIndex: number, input: any) => {
        const unlockScript = [
            input.tapScriptSig[scriptIdx].signature,
            preimage
        ];
        const witness = unlockScript
            .concat(tapLeafScript.script)
            .concat(tapLeafScript.controlBlock);

        return {
            finalScriptWitness: witnessStackToScriptWitness(witness),
        }
    }
    psbt.signInput(txinIndex, keyAlice);
    psbt.finalizeInput(txinIndex, customFinalizer);

    const tx = psbt.extractTransaction();
    const txid = tx.getId();
    console.log(`txid=${txid}`);
    console.log(`tx= ${tx.toHex()}`);
}

/**
 * Helper function that produces a serialized witness script
 * https://github.com/bitcoinjs/bitcoinjs-lib/blob/1f92ada3fda587c1c0a6aa93649afa04e8382b93/test/integration/csv.spec.ts#L480
 */
export function witnessStackToScriptWitness(witness: Buffer[]) {
    let buffer = Buffer.allocUnsafe(0)

    function writeSlice(slice: Buffer) {
        buffer = Buffer.concat([buffer, Buffer.from(slice)])
    }

    function writeVarInt(i: number) {
        const currentLen = buffer.length;
        const varintLen = varuint.encodingLength(i)

        buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)])
        varuint.encode(i, buffer, currentLen)
    }

    function writeVarSlice(slice: Buffer) {
        writeVarInt(slice.length)
        writeSlice(slice)
    }

    function writeVector(vector: Buffer[]) {
        writeVarInt(vector.length)
        vector.forEach(writeVarSlice)
    }

    writeVector(witness)

    return buffer
}

(async () => {
    await taptree();
})();
