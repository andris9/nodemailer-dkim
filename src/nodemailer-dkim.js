'use strict';

// Code is heavily influenced by Haraka: https://github.com/haraka/Haraka/blob/master/plugins/dkim_sign.js

var Stream = require('stream').Stream;
var crypto = require('crypto');
var util = require('util');
var dns = require('dns');
var punycode = require('punycode');

function indexOfLF(buf, maxlength) {
    for (var i = 0; i < buf.length; i++) {
        if (maxlength && (i === maxlength)) {
			break;
		}
        if (buf[i] === 0x0a) {
			return i;
		}
    }
    return -1;
}

function parseHeader(line) {
	var m = /^([^:]+):\s*((?:.|[\r\n])*)$/.exec(line);
	if (!m) {
		return null;
	}
	var keyValue = {};
	var key = m[1].toLowerCase();
	var value = m[2].trim();
	value = value.replace(/\r\n([\t ]+)/g, "$1");
	value = value.replace(/[\t ]+/g, ' ');
	value = value.replace(/[\t ]+(\r?\n)$/, "$1");
	keyValue[key] = value;
	return keyValue;
}

function DKIMSigner(options) {
    this.options = options || {};
    Stream.call(this);

	this.writable = true;
	this.readble = true;

	this.callback = options.callback;
	this.message = options.message;
    this.domain = options.domainName;
    this.selector = options.keySelector;
    this.privKey = options.privateKey;
	this.headers_to_sign = [
		'from',
		'sender',
		'reply-to',
		'subject',
		'to',
		'cc',
		'mime-version',
		'content-type',
		'content-transfer-encoding',
		'content-id',
		'content-description',
		'resent-date',
		'resent-from',
		'resent-sender',
		'resent-to',
		'resent-cc',
		'resent-message-id',
		'in-reply-to',
		'references',
		'list-id',
		'list-help',
		'list-unsubscribe',
		'list-subscribe',
		'list-post',
		'list-owner',
		'list-archive'
	];
    this.headers = [];
	this.signed_headers = [];

    this.found_eoh = false;
    this.buffer = {
        ar: [],
        len: 0
    };
    this.line_buffer = {
        ar: [],
        len: 0
    };
    this.hash = crypto.createHash('SHA256');
    this.signer = crypto.createSign('RSA-SHA256');
}
util.inherits(DKIMSigner, Stream);

DKIMSigner.prototype.write = function(buf) {
	this.emit('data', buf);
    // Merge in any partial data from last iteration
    if (this.buffer.ar.length) {
        this.buffer.ar.push(buf);
        this.buffer.len += buf.length;
        var nb = Buffer.concat(this.buffer.ar, this.buffer.len);
        buf = nb;
        this.buffer = {
            ar: [],
            len: 0
        };
    }
    var offset = 0;
    while ((offset = indexOfLF(buf)) !== -1) {
        var line = buf.slice(0, offset + 1);
        if (buf.length > offset) {
            buf = buf.slice(offset + 1);
        }
		// Check for LF line endings and convert to CRLF if necessary
		if (line[line.length - 2] !== 0x0d) {
			line = Buffer.concat([line.slice(0, line.length - 1), new Buffer("\r\n")], line.length + 1);
		}
        // Look for CRLF
        if (line.length === 2 && line[0] === 0x0d && line[1] === 0x0a) {
            // Look for end of headers marker
            if (!this.found_eoh) {
                this.found_eoh = true;
            } else {
                // Store any empty lines so that we can discard
                // any trailing CRLFs at the end of the message
                this.line_buffer.ar.push(line);
                this.line_buffer.len += line.length;
            }
        } else {
            if (!this.found_eoh) {
				if (line[0] === 0x20 || line[0] === 0x09) {
					// Header continuation
					this.headers[this.headers.length - 1] += line.toString('utf-8');
				} else {
					this.headers.push(line.toString('utf-8'));
				}
				continue;
			}
            if (this.line_buffer.ar.length) {
                // We need to process the buffered CRLFs
                var lb = Buffer.concat(this.line_buffer.ar, this.line_buffer.len);
                this.line_buffer = {
                    ar: [],
                    len: 0
                };
                this.hash.update(lb);
            }
            this.hash.update(line);
        }
    }
    if (buf.length) {
        // We have partial data...
        this.buffer.ar.push(buf);
        this.buffer.len += buf.length;
    }
	return true;
};

DKIMSigner.prototype.end = function() {
    if (this.buffer.ar.length) {
        this.buffer.ar.push(new Buffer("\r\n"));
        this.buffer.len += 2;
        var le = Buffer.concat(this.buffer.ar, this.buffer.len);
        this.hash.update(le);
        this.buffer = {
            ar: [],
            len: 0
        };
    }
	var bodyhash = this.hash.digest('base64');

	var key;
	var value;
	var keyValue;
	var line;
	for (var i = 0, len = this.headers.length; i < len; i++) {
		line = this.headers[i];
		keyValue = parseHeader(line);
		key = Object.keys(keyValue)[0];
		value = keyValue[key];
		if (this.headers_to_sign.indexOf(key) !== -1) {
			this.signer.update(key + ':' + value + "\r\n");
			this.signed_headers.push(key);
		}
	}
	var dkim_header = 'v=1;a=rsa-sha256;bh=' + bodyhash +
                      ';c=relaxed/simple;d=' + this.domain +
                      ';h=' + this.signed_headers.join(':') +
                      ';s=' + this.selector +
                      ';b=';
    this.signer.update('dkim-signature:' + dkim_header);
	var signature = this.signer.sign(this.privKey, 'base64');
	dkim_header += signature;
	this.message.addHeader({
		'DKIM-Signature': dkim_header
	});
	this.callback();
	this.emit('end');
};

/**
 * Verifies if selected settings are valid (private key matches the publick key listed in DNS)
 *
 * @param {Function} callback Callback function with the result
 */
function verifyKeys(options, callback) {
    var domain = punycode.toASCII([options.keySelector, '_domainkey', options.domainName].join('.'));
    dns.resolveTxt(domain, function(err, result) {
        if (err) {
            return callback(err);
        }

        if (!result || !result.length) {
            return callback(new Error('Selector not found (%s)', domain));
        }

        var data = {};
        [].concat(result[0] || []).join('').split(/;/).forEach(function(row) {
            var key, val;
            row = row.split('=');
            key = (row.shift() || '').toString().trim();
            val = (row.join('=') || '').toString().trim();
            data[key] = val;
        });

        if (!data.p) {
            return callback(new Error('DNS TXT record does not seem to be a DKIM value', domain));
        }

        var pubKey = '-----BEGIN PUBLIC KEY-----\n' + data.p.replace(/.{78}/g, '$&\n') + '\n-----END PUBLIC KEY-----';

        try {
            var sign = crypto.createSign('RSA-SHA256');
            sign.update('nodemailer');
            var signature = sign.sign(options.privateKey, 'hex');
            var verifier = crypto.createVerify('RSA-SHA256');
            verifier.update('nodemailer');

            if (verifier.verify(pubKey, signature, 'hex')) {
                return callback(null, true);
            } else {
                return callback(new Error('Verification failed, keys do not match'));
            }
        } catch (E) {
            callback(E);
        }
    });
}

module.exports.DKIMSigner = module.exports.signer = function(options) {
    return function(mail, callback) {
		options.message = mail.message;
		options.callback = callback;
		var stream = mail.message.createReadStream();
		var sign = new DKIMSigner(options);
		stream.pipe(sign);
    };
};

module.exports.verifyKeys = verifyKeys;
