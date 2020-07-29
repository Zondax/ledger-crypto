<template>
  <div class="Ledger">
    <!--
        Commands
    -->
    <button @click="getVersion">
      Get Version
    </button>

    <button @click="appInfo">
      AppInfo
    </button>

    <button @click="getAddress">
      Get Pubkey
    </button>

    <button @click="showAddress">
      Show Pubkey
    </button>

    <button @click="signExampleTx">
      Sign Example TX
    </button>
    <!--
        Commands
    -->
    <ul id="ledger-status">
      <li v-for="item in ledgerStatus" :key="item.index">
        {{ item.msg }}
      </li>
    </ul>
  </div>
</template>

<script>
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
import CryptoApp from "@zondax/ledger-crypto";

const EXAMPLE_PATH = `m/44'/394'/0/0/0`;

export default {
  name: "Ledger",
  props: {},
  data() {
    return {
      deviceLog: [],
    };
  },
  computed: {
    ledgerStatus() {
      return this.deviceLog;
    },
  },
  methods: {
    log(msg) {
      this.deviceLog.push({
        index: this.deviceLog.length,
        msg,
      });
    },
    async getTransport() {
      let transport = null;

      this.log(`Trying to connect via WebUSB...`);
      try {
        transport = await TransportWebUSB.create();
      } catch (e) {
        this.log(e);
      }
      return transport;
    },
    async getVersion() {
      const transport = await this.getTransport();

      try {
        this.deviceLog = [];
        const app = new CryptoApp(transport);

        // now it is possible to access all commands in the app
        const response = await app.getVersion();
        if (response.returnCode !== CryptoApp.ERROR_CODE.NoError) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async appInfo() {
      const transport = await this.getTransport();
      try {
        this.deviceLog = [];
        const app = new CryptoApp(transport);

        // now it is possible to access all commands in the app
        const response = await app.appInfo();
        if (response.returnCode !== 0x9000) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async getAddress() {
      const transport = await this.getTransport();
      try {
        this.deviceLog = [];
        const app = new CryptoApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        // now it is possible to access all commands in the app
        response = await app.getAddressAndPubKey(EXAMPLE_PATH);
        if (response.returnCode !== CryptoApp.ERROR_CODE.NoError) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async showAddress() {
      const transport = await this.getTransport();
      this.deviceLog = [];
      try {
        const app = new CryptoApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        // now it is possible to access all commands in the app
        this.log("Please click in the device");
        response = await app.showAddressAndPubKey(EXAMPLE_PATH);
        if (response.returnCode !== CryptoApp.ERROR_CODE.NoError) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async signExampleTx() {
      const transport = await this.getTransport();

      try {
        this.deviceLog = [];
        const app = new CryptoApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        const message = Buffer.from("00020000000000000000040009cbc2ce0dd314d5a7c658c866a4faf2d8510c6912313859eee908322bd7daf5e803000000000000010000000000000000000004036b3e5b7744134ac0556ace88b098a057014afb82701b1b1ba49ea04b09fea29b000100000000000000", "hex");
        response = await app.sign(EXAMPLE_PATH, message);

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

button {
  padding: 5px;
  font-weight: bold;
  font-size: medium;
}

ul {
  padding: 10px;
  text-align: left;
  alignment: left;
  list-style-type: none;
  background: black;
  font-weight: bold;
  color: greenyellow;
}
</style>
