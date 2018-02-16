/* eslint-disable no-console */

const dgram = require('dgram');
const inquirer = require('inquirer');
const os = require('os');
const radius = require('radius');
const yargs = require('yargs');

const argv = yargs
  .usage('RADIUS Client CLI\nUsage: $0')
  .example('$0 --secret secret')
  .alias('h', 'host')
  .describe('host', 'RADIUS server hostname')
  .default('host', 'localhost')
  .string('host')
  .alias('p', 'port')
  .describe('port', 'RADIUS server port')
  .default('port', 1812)
  .number('port')
  .alias('s', 'secret')
  .describe('secret', 'RADIUS shared secret')
  .string('secret')
  .demandOption('secret')
  .alias('u', 'username')
  .describe('username', 'RADIUS login username')
  .string('username')
  .alias('w', 'password')
  .describe('password', 'RADIUS login password')
  .string('password')
  .argv;

console.log(`RADIUS Server: ${argv.host}`);
console.log(`RADIUS Port: ${argv.port}`);
console.log(`RADIUS Secret: ${argv.secret}`);
console.log();

const client = dgram.createSocket('udp4');
const sentPackets = {};
let identifier = 0;

function sendPacket(attributes) {
  identifier += 1;
  const packet = {
    code: 'Access-Request',
    secret: argv.secret,
    identifier,
    attributes
  };
  const encoded = radius.encode(packet);
  sentPackets[packet.identifier] = { raw_packet: encoded, secret: packet.secret };

  console.log();
  console.log(`Access-Request [${packet.identifier}] => ${argv.host}:${argv.port}`);

  client.send(encoded, 0, encoded.length, argv.port, argv.host);
}

function login() {
  console.log('----------------------------');
  console.log('Login');
  const questions = [];

  if (!argv.username) {
    questions.push({ type: 'input', name: 'username', message: 'UserName:' });
  }

  if (!argv.password) {
    questions.push({ type: 'input', name: 'password', message: 'Password:' });
  }

  inquirer.prompt(questions).then((answers) => {
    sendPacket([
      ['NAS-IP-Address', '127.0.0.1'],
      ['User-Name', argv.username || answers.username],
      ['User-Password', argv.password || answers.password]
    ]);
  }).catch(err => {
    console.log(err);
  });
}

client.on('message', (msg) => {
  const response = radius.decode({ packet: msg, secret: argv.secret });
  const request = sentPackets[response.identifier];
  const isValid = radius.verify_response({
    response: msg,
    request: request.raw_packet,
    secret: request.secret
  });

  if (isValid) {
    console.log(`${argv.host}:${argv.port} => ${response.code} [${response.identifier}]`);
    console.log();

    switch (response.code) {
      case 'Access-Challenge': {
        const questions = [{
          type: 'input',
          name: 'challenge',
          suffix: os.EOL,
          message: response.attributes['Reply-Message']
        }];

        inquirer.prompt(questions).then((answers) => {
          sendPacket([
            ['State', response.attributes.State],
            ['User-Name', '-'],
            ['User-Password', answers.challenge]
          ]);
        }).catch(err => {
          console.log(err);
        });
        break;
      }
      case 'Access-Accept':
        console.log('User Authenticated!');
        client.close();
        break;
      case 'Access-Reject':
        console.log('User Rejected!');
        client.close();
        break;
      default:
    }
  } else {
    console.log(`${argv.host}:${argv.port} => ${response.code} [${response.identifier}] - Invalid Response`);
  }
});

login();
