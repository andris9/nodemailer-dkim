'use strict';

var chai = require('chai');
var stubTransport = require('nodemailer-stub-transport');
var dkim = require('../src/nodemailer-dkim');
var nodemailer = require('nodemailer');
var transport = nodemailer.createTransport(stubTransport());
var fs = require('fs');
var sinon = require('sinon');

var expect = chai.expect;
chai.Assertion.includeStack = true;

describe('nodemailer-dkim tests', function() {
    it('should add valid signature', function(done) {
		transport.use('stream', dkim.signer({
            domainName: 'node.ee',
            keySelector: 'dkim',
            privateKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem')
        }));

		transport.sendMail({
			from: 'andris@node.ee',
			to: 'andris@kreata.ee',
			subject: 'Test',
			html: '<p>Hello World!</p>\n',
			date: Date(1465345157 * 1000)
		}, function(err, info){
			var raw = info.response.toString();
			if (raw.indexOf('v=1;a=rsa-sha256;bh=lzycLjmx+7cNnIDxD6kePwIkOs3o748Ts3L460RwrNE=;c=relaxed/simple;d=node.ee;h=content-type:from:to:subject:content-transfer-encoding:mime-version;s=dkim;b=KtGiOCvtbdch2AHBPaCFZUPx1aHA8k9xeZrmrikDBOsPzyrLDwFC1VQwf9kKLDlvGX2wPdMU0w5xD9tL1si/jljIRZPjJFlH/sUlaXAsjjxPUCILTnz/ulbvF5gWwyuL') !== -1) {
				done();
			}
		});
    });

    it('should verify valid keys', function(done) {
        var dns = require('dns');
        sinon.stub(dns, 'resolveTxt').yields(null, [ [' p = MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhANCx7ncKUfQ8wBUYmMqq6ky8rBB0NL8knBf3+uA7q/CSxpX6sQ8NdFNtEeEd7gu7BWEM7+PkO1P0M78eZOvVmput8BP9R44ARpgHY4V0qSCdUt4rD32nwfjlGbh8p5ua5wIDAQAB'] ]);

        dkim.verifyKeys({
            domainName: 'node.ee',
            keySelector: 'dkim',
            privateKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem')
        }, function(err, success) {
            expect(err).to.not.exist;
            expect(success).to.be.true;
            dns.resolveTxt.restore();
            done();
        });
    });

    it('should not verify missing keys', function(done) {
        var dns = require('dns');
        sinon.stub(dns, 'resolveTxt').yields(null, []);

        dkim.verifyKeys({
            domainName: 'node.ee',
            keySelector: 'dkim',
            privateKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem')
        }, function(err) {
            expect(err).to.exist;
            dns.resolveTxt.restore();
            done();
        });
    });

    it('should not verify non matching keys', function(done) {
        var dns = require('dns');
        sinon.stub(dns, 'resolveTxt').yields(null, [ ['p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFDiKg3O4hdG5iehr5MNxMgrJNMUh6hgWekILDZg2I8WGERJTFZpnspUT1wgoVRziVzGB7ORbVOZEPdZy7noNSTpx5hDgHie/8cO1Q9O/IIX6Mx4qfQL21m0d1zZRbCo6wdO/cwXMoqOZN6ijpFsLFBMNanJ7AysIXiu6GeYLxwQIDAQAB'] ]);

        dkim.verifyKeys({
            domainName: 'node.ee',
            keySelector: 'dkim',
            privateKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem')
        }, function(err) {
            expect(err).to.exist;
            dns.resolveTxt.restore();
            done();
        });
    });
});
