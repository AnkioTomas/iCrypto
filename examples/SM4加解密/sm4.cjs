const fs = require('fs');
const { sm4 } = require("sm-crypto");
const yargs = require('yargs');
const { hideBin } = require('yargs/helpers');

const argv = yargs(hideBin(process.argv))
  .option('vkey', {
    alias: 'v',
    describe: 'Encryption key',
    type: 'string',
    demandOption: true
  })
  .option('gkey', {
    alias: 'g',
    describe: 'Initialization vector for encryption',
    type: 'string',
    demandOption: true
  })
  .option('operationType', {
    alias: 'o',
    describe: 'Type of operation',
    type: 'number',
    demandOption: true
  })
  .option('dataDir', {
    alias: 'd',
    describe: 'Directory for data files',
    type: 'string',
    demandOption: true
  })
  .argv;

// Constants for operation types
const RequestFromClient = "0";
const RequestToServer = "1";
const ResponseFromServer = "2";
const ResponseToClient = "3";

function getRequestBody() {
    return fs.readFileSync(`${argv.dataDir}/body.txt`).toString();
}

function setRequestBody(data) {
    fs.writeFileSync(`${argv.dataDir}/body.txt`, data);
}

function getResponseBody() {
    return fs.readFileSync(`${argv.dataDir}/response_body.txt`).toString();
}

function setResponseBody(data) {
    fs.writeFileSync(`${argv.dataDir}/response_body.txt`, data);
}

function encrypt(msg) {
    return sm4.encrypt(msg, argv.vkey, {
        mode: "cbc",
        iv: argv.gkey
    });
}

function decrypt(msg) {
    return sm4.decrypt(msg, argv.vkey, {
        mode: "cbc",
        iv: argv.gkey
    });
}

switch (argv.operationType.toString()) {
    case RequestFromClient:
        setRequestBody(decrypt(getRequestBody()));
        break;
    case RequestToServer:
        setRequestBody(encrypt(getRequestBody()));
        break;
    case ResponseFromServer:
        let responseBody = JSON.parse(getResponseBody());
        responseBody.data = JSON.parse(decrypt(responseBody.data));
        setResponseBody(JSON.stringify(responseBody));
        break;
    case ResponseToClient:
        let responseBody2 = JSON.parse(getResponseBody());
        responseBody2.data = encrypt(JSON.stringify(responseBody2.data));
        setResponseBody(JSON.stringify(responseBody2));
        break;
}

console.log("success");