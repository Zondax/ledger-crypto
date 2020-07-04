/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import CryptoApp from "@zondax/ledger-crypto";
import secp256k1 from "secp256k1/elliptic";
import blake3 from "blake3-js"

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    , X11: true
};

jest.setTimeout(15000)

function compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount) {
    for (let i = 0; i < snapshotCount; i++) {
        const img1 = Zemu.LoadPng2RGB(`${snapshotPrefixTmp}${i}.png`);
        const img2 = Zemu.LoadPng2RGB(`${snapshotPrefixGolden}${i}.png`);
        expect(img1).toEqual(img2);
    }
}

describe('Basic checks', function () {
    test('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
        } finally {
            await sim.close();
        }
    });

    test('get app version', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());
            const resp = await app.getVersion();

            console.log(resp);

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");
            expect(resp).toHaveProperty("testMode");
            expect(resp).toHaveProperty("major");
            expect(resp).toHaveProperty("minor");
            expect(resp).toHaveProperty("patch");
        } finally {
            await sim.close();
        }
    });

    test('get address - transfer', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const response = await app.getAddressAndPubKey("m/44'/394'/0'/0/0");
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "048ef50054db1b8c5ff9b02640a25463a37ca7d4249da43b4e6f4ea8f7af70daec5e276294642dec9dc28079397d6962cc32d3909e92995167768fbde7250424d9";
            const expected_address = "cro1n97t35jymgksmh73mh0zj3qx539k3hg4pfhmncake4ssm3z7rreqzkza53";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);

        } finally {
            await sim.close();
        }
    });

    test('get address - staking', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const response = await app.getAddressAndPubKey("m/44'/394'/1'/0/0");
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "04eda422888bff3b3fa957ab9a509b6ae70c1249c9b9b35f1832aeb2e9a4f94b86076054d2641464e55f85e0c6d27d7dcebd60386f6178dec5e77a2a03330952aa";
            const expected_address = "f3c7d0d3439c174b9ce8178c2d2ea95dc1f45c28";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);

        } finally {
            await sim.close();
        }
    });

    test('show address - transfer', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/0'/0/1");
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "04db0c6d56193c5b12fa2588d4254db1eb90d502852f3bd71beb8cd7d5eda3747cae746dfc75bfcbc48c1664fc494828daf6683e9fa331875ac894d8a2a296aa7e";
            const expected_address = "cro1d0dxrfy0jf4mr0tnrkdaaay3v706z5hfdhw42ac8f20jd9w7u9lsrqcfjz";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address - transfer - expert', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            await sim.clickRight();
            await sim.clickBoth();

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/0'/0/1");
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "04db0c6d56193c5b12fa2588d4254db1eb90d502852f3bd71beb8cd7d5eda3747cae746dfc75bfcbc48c1664fc494828daf6683e9fa331875ac894d8a2a296aa7e";
            const expected_address = "cro1d0dxrfy0jf4mr0tnrkdaaay3v706z5hfdhw42ac8f20jd9w7u9lsrqcfjz";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address - transfer - testnet', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/1'/0'/0/1");
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "0457605444d19911c74882a01ccd708973b0b7672c89502f93c549675d1e9c0ee0a6814f3bf0f04a012fa5037b1e7f7e54e72a99a7c34adfc0fabee1948219b86d";
            const expected_address = "tcro1fz2t9gwnut4lsnm3tfrdch4fdulwzp7tkc5um8jxpqfswk3f0lesvaztj5";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address - staking', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/1'/0/1");
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "042eec2a1e00ece871fb2697bd7cb44732ef9664ac543c9b57916a691bf63fd22ae5f534194eadeee84d6472e116b41cf9a674e92e772d574b6f3b032c9becfa76";
            const expected_address = "c4bb0afc4c1639efbc1ea06aee8847e79b8fa00b";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address - staking - testnet', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/1'/1'/0/1");
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "042bd4f7bbeeea93f843131c7e38d73b0a79eb1a6e9a23d00e8e0779df7c37305b5d8bc52930ebacf477f57d8340c3fadf8ffbc5027caa2b5ac2d5b0f833a69a05";
            const expected_address = "a3b92de76e57805d29aaefe171f6230e22b1ccb9";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('sign', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const path = "m/44'/394'/1'/0/1";
            const blobStr = "010000bce02627ca9daa2af92412cb9998aa59df1270790000000000000000e803000000000000000001000000000000000001686d772b75f229beb68b761432148eaa762d6bc38d89cc76b90799e1cea7d0ab34b5dd4740a0a1dc06f4d7f25f9747b8b6c14e50a6176cc6e55e9f3005556cc2"
            const blob = Buffer.from(blobStr, "hex")

            const addrResponse = await app.getAddressAndPubKey(path);
            console.log(addrResponse)

            const pk = Uint8Array.from(addrResponse.publicKey)
            const blobToHash = blob.slice(2, blob.length - 66)
            const msgHash = Uint8Array.from(blake3
                .newRegular()
                .update(blobToHash)
                .finalize(32, "bytes"));
            console.log("Blob To Hash: ", Buffer.from(blobToHash).toString("hex"))
            console.log("TX ID       :  ", Buffer.from(msgHash).toString("hex"))

            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign(path, blob);
            await Zemu.sleep(2000);

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            let signatureResponse = await signatureRequest;
            console.log(signatureResponse)
            expect(signatureResponse.returnCode).toEqual(0x9000);

            // Now verify the signature
            const signature = secp256k1.signatureImport(Uint8Array.from(signatureResponse.signatureDER));
            const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk);
            expect(signatureOk).toEqual(true);
        } finally {
            await sim.close();
        }
    });

});
