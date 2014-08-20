var radius      = require('radius');
var dgram       = require("dgram");
var util        = require('util');
var inquirer    = require('inquirer');


var argv = require('yargs')
    .usage('RADIUS Client CLI\nUsage: $0')
    .example('$0 --h localhost --p 1812 --s secret')
    .default({ host: 'localhost', port: 1812, s: 'grumble,grumble' })
    .alias('h', 'host')
    .describe('host', 'RADIUS server hostname')
    .alias('p', 'port')
    .describe('port', 'RADIUS server port')
    .alias('s', 'secret')
    .describe('secret', 'RADIUS secret')
    .demand('host', 'port', 'secret')
    .argv
;


console.log();
console.log('loading configuration...');
console.log();
console.log('RADIUS Server:\n\t' + argv.host);
console.log('RADIUS Port:\n\t' + argv.port);
console.log('RADIUS Secret:\n\t' + argv.secret);
console.log();


var client = dgram.createSocket("udp4");
var identifier = 0;
var sent_packets = {};

var login= function() {
	console.log('----------------------------');
	console.log("Login");
	var questions = [
		{
			type: "input", name: "username", message: "UserName:"
		},
		{
			type: "input", name: "password", message: "Password:"
		}
	];
	inquirer.prompt(questions, function(answers) {
		var packet = {
			code: "Access-Request",
			secret: argv.secret,
			identifier: identifier++,
			attributes: [
				['NAS-IP-Address', '127.0.0.1'],
				['User-Name', answers.username],
				['User-Password', answers.password]
			]
		};
		var encoded = radius.encode(packet);
		sent_packets[packet.identifier] = {
			raw_packet: encoded,
			secret: packet.secret
		};
		console.log();
		console.log('Access-Request [' + packet.identifier + '] => ' + argv.host + ':' + argv.port);
		client.send(encoded, 0, encoded.length, argv.port, argv.host);
	});
}

client.on('message', function(msg, rinfo) {
	var questions, state, replyMessage;
	var response = radius.decode({packet: msg, secret: argv.secret});
	var request = sent_packets[response.identifier];
	var valid_response = radius.verify_response({
		response: msg,
		request: request.raw_packet,
		secret: request.secret
	});

	if (valid_response) {
		console.log(argv.host + ':' + argv.port + ' => ' + response.code + ' [' + response.identifier + ']');
		console.log();
		switch (response.code) {
			case 'Access-Challenge':
				state = response.attributes['State'];
				replyMessage = response.attributes['Reply-Message'];

				questions = [
					{
						type: "input", name: "factor", message: replyMessage + '\r\n'
					}
				];
				inquirer.prompt(questions, function(answers) {
					var packet = {
						code: "Access-Request",
						secret: argv.secret,
						identifier: identifier++,
						attributes: [
							['State', state],
							['User-Name', state],
							['User-Password', answers.factor]
						]
					};
					var encoded = radius.encode(packet);
					sent_packets[packet.identifier] = {
						raw_packet: encoded,
						secret: packet.secret
					};
					console.log();
					console.log('Access-Request [' + packet.identifier + '] => ' + argv.host + ':' + argv.port );
					client.send(encoded, 0, encoded.length, argv.port, argv.host);
				});
				break;
			case 'Access-Accept':
				console.log("User Authenticated!")
				client.close();
				break;
			case 'Access-Reject':
				console.log("User Rejected!")
				login();
				break;
		}
	} else {
		console.log(argv.port + ':' + argv.host + ' => ' + response.code + ' [' + packet.identifier + '] - Invalid Response');
	}
});

// Prompt for Credentials
login();
