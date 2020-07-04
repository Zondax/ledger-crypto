import Zemu from "@zondax/zemu";
import CryptoApp from "@zondax/ledger-crypto";
import path from "path";

const APP_PATH = path.resolve(`./../../app/bin/app.elf`);

const seed = "equip will roof matter pink blind book anxiety banner elbow sun young"
const SIM_OPTIONS = {
    logging: true,
    start_delay: 3000,
    X11: true,
    custom: `-s "${seed}" --color LAGOON_BLUE`
};

async function beforeStart() {
    process.on("SIGINT", () => {
        Zemu.default.stopAllEmuContainers(function () {
            process.exit();
        });
    });
    await Zemu.default.checkAndPullImage();
}

async function beforeEnd() {
    await Zemu.default.stopAllEmuContainers();
}

async function debugScenario1(sim, app) {
    const response = app.showAddressAndPubKey("m/44'/394'/0'/0/0");
    await Zemu.default.sleep(2000);
    await sim.clickBoth();
    await response;
    console.log(response)
}

async function debugScenario2(sim, app) {
    // Here you can customize what you want to do :)
    // Do not await.. we need to click asynchronously
    const blobStr = "010000bce02627ca9daa2af92412cb9998aa59df1270790000000000000000e803000000000000000001000000000000000001686d772b75f229beb68b761432148eaa762d6bc38d89cc76b90799e1cea7d0ab34b5dd4740a0a1dc06f4d7f25f9747b8b6c14e50a6176cc6e55e9f3005556cc2"
    const blob = Buffer.from(blobStr, "hex")

    // Do not await.. we need to click asynchronously
    const signatureRequest = app.sign("m/44'/394'/0'/0/0", blob);
    await Zemu.default.sleep(2000);

    // Click right + double
    await sim.clickBoth();
    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log(signature)
}

async function main() {
    await beforeStart();

    if (process.argv.length > 2 && process.argv[2] === "debug") {
        SIM_OPTIONS["custom"] = SIM_OPTIONS["custom"] + " --debug";
    }

    const sim = new Zemu.default(APP_PATH);

    try {
        await sim.start(SIM_OPTIONS);
        const app = new CryptoApp.default(sim.getTransport());

        ////////////
        /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

        await debugScenario1(sim, app);

        /// TIP

    } finally {
        await sim.close();
        await beforeEnd();
    }
}

(async () => {
    await main();
})();
