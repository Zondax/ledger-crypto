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

import { expect, test } from "jest";
import Zemu from "@zondax/zemu";
import CryptoApp from "@zondax/ledger-crypto";

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
//    ,X11: true
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

            const response = await app.getAddressAndPubKey("m/44'/394'/0'/0/0", true);
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "038ef50054db1b8c5ff9b02640a25463a37ca7d4249da43b4e6f4ea8f7af70daec5e276294642dec9dc28079397d6962cc32d3909e92995167768fbde7250424d9";
            const expected_address = "cro1cvdtpjrhm33hv22vxltw00e60kcccvgat58jw8m49536nfxnywh86ps92";

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

            const response = await app.getAddressAndPubKey("m/44'/394'/1'/0/0", true);
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "02eda422888bff3b3fa957ab9a509b6ae70c1249c9b9b35f1832aeb2e9a4f94b86076054d2641464e55f85e0c6d27d7dcebd60386f6178dec5e77a2a03330952aa";
            const expected_address = "D218B4DE1EF21BE0894BB008F3C7D0D3439C174B";

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

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/0'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "02db0c6d56193c5b12fa2588d4254db1eb90d502852f3bd71beb8cd7d5eda3747cae746dfc75bfcbc48c1664fc494828daf6683e9fa331875ac894d8a2a296aa7e";
            const expected_address = "cro1px5fjx6xrrcs9cs2tk4pas0a94852zgfzt5ykmzqztwr5xuspehxlamy3";

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

            const addrRequest = app.showAddressAndPubKey("m/44'/1'/0'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "0357605444d19911c74882a01ccd708973b0b7672c89502f93c549675d1e9c0ee0a6814f3bf0f04a012fa5037b1e7f7e54e72a99a7c34adfc0fabee1948219b86d";
            const expected_address = "tcro107730d7dtfa70uvz43mh5mfd8enwkc58wzmvd97y39ydp6ht7ga9r87j8";

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

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/1'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "022eec2a1e00ece871fb2697bd7cb44732ef9664ac543c9b57916a691bf63fd22ae5f534194eadeee84d6472e116b41cf9a674e92e772d574b6f3b032c9becfa76";
            const expected_address = "2CEC4223FD70F6B109E5EE03C4BB0AFC4C1639EF";

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

            const addrRequest = app.showAddressAndPubKey("m/44'/1'/1'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "032bd4f7bbeeea93f843131c7e38d73b0a79eb1a6e9a23d00e8e0779df7c37305b5d8bc52930ebacf477f57d8340c3fadf8ffbc5027caa2b5ac2d5b0f833a69a05";
            const expected_address = "112AFD6303057B97C6396F26A3B92DE76E57805D";

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

            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/394'/0'/0/0", "1234");
            await Zemu.sleep(2000);

            // Click right + double
            await sim.clickRight();
            await sim.clickBoth();

            let signature = await signatureRequest;
            console.log(signature)

            expect(signature.returnCode).toEqual(0x9000);

            // TODO: Verify signature
        } finally {
            await sim.close();
        }
    });

});
