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

    test('get address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const response = await app.getAddressAndPubKey("m/44'/394'/5'/0/0", true);
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "02075a6c6c4d706621655c3fcd4920241b54627b9d40df0279585c03ba0c1fc3fb18a1182d3716ec909ef09cb8b9b4a1ef9bc37caef5d9c4900787825db0f6fcd2";
            const expected_address = "cro10kw8kzz5xkq997gnxelh7du9662tqn855h4geq";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);

        } finally {
            await sim.close();
        }
    });

    test('show address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/394'/5'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "038e53646a36586f9c68bc363bac8e8613de7a9fbf2d9ddc96bbb7eb0bf02024786156f1f0722d222b5f0ab7fed8cbe933766463f0bb9de1e1ba22fc34178dbc25";
            const expected_address = "cro1ualms2z7p79elw4sskhh50hwjyje5rqy8k657w";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address - testnet', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new CryptoApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/1'/5'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "02c4f797d6efcfb22fd34d3ff5874805f6043b2a6da2aff947e10aa5ad87f13e69447967cbf73d38a6bb211aa604dd7f81e2dcc04db545e2e8138b1caae9410c06";
            const expected_address = "tcro1rt5ysktsqsxqtgr5dsmv48ca4qaauyfcg900wm";

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
            const signatureRequest = app.sign("m/44'/394'/5'/0/0", "1234");
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
