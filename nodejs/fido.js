"use strict";

var jwkToPem = require('jwk-to-pem')
var crypto = require('crypto');

const a = "AQAAAAA";
const pk = '{ "kty" : "RSA", "alg" : "RS256", "ext" : false, "n" : "lylQRV6_MEurzIUqUHZ19vPk_WXIxkKAMKsrgVYZxQiuBGBOnsNqArkD0CDOON6Q1Wtlwmm-_BLRDQlFc4m1FQC6Tv5CbO4ojeb3a7mFbc7_C5vL-vmvr3-h3loev0Mg5id0_06M22dZ07tVfU64ySZNSBK44zQ1-0Net0tSKenf2cR_9vZIhaE3zMVrBnB1JXUFb5lpdHxkmLEtgzBtGe47Plvy0ghaUDNgpSNpYeK_czkDwCm6g_tMFd-kDYmB1LbA75f7gvR7d6o4-Q67CT-iqVUo0LqOXyQI1r6SJNGqM_5JoPi2ryQh5Hq1PIJJeuYr44h5Xz8A181Ga_JZCw", "e" : "AQAB" }';
const d = 'ew0KCSJjaGFsbGVuZ2UiIDogImFhYSINCn0A';
const s = 'CHFTbWVDWGZQP1Y4ydO3wZSNVXqbXUDM2zEDkxsoLC661bgSkFzCPpXC_58YUla94EARnBhAeDQBKa1O12cp7K2E5sjn14cM9mfkCkxTAGzWe8Av5yiCN2JFnRZy02VWADuSVJzdOVEI8bwAWO713-WwltumDanFXA-Lwa6_9sNLJe9J4Sx5hM9joP-iVlth_pGxxILQhQR-3500zcuMYltwkcr0V5tYl7obOEEfPUhe0lxeSvBIiuCFqoPmouirEIFGKQ2o2PVh7bhfg03e2nWSWNOQ4kZV1ZkNxnoTGI90RapPnwYoWpucV3gyJBF-SJS9Y_yfu7EQkbdsuyv9Dw';
const challenge = 'aaa';

/*
 *  fidoAuthenticator contains the logic for validating the signature returned from getAssertion in the
 *  browser. This code is currently specific to the early implementation in Microsoft Edge and will need to change
 *  when the final standard is adopted. This code would run on the server in order to validate that the user
 *  really is able to validate using the credentials previously created with the makeCredential API.
 *
 *  The public key in pk would have been stored on the server using the results of makeCredential. The challenge
 *  would have been created on ther server and sent to the client for use in the getAssertion call. The other
 *  parameters are returned by getAssertion and transmitted from the browser to the server for validation. 
 */
var fidoAuthenticator = {
	validateSignature: function (pk,d,a,s,challenge) {
		var c = new Buffer(d,'base64');
		var cc = JSON.parse(c.toString().replace(/\0/g,''));
		if(cc.challenge!=challenge) return false;

		// Hash c with sha256
		const hash = crypto.createHash('sha256');
		hash.update(c);
		var h = hash.digest();

		var verify = crypto.createVerify('RSA-SHA256');
		verify.update(new Buffer(a,'base64'));
		verify.update(h);
		return verify.verify(jwkToPem(JSON.parse(pk)),s,'base64');
	}
};

console.log(fidoAuthenticator.validateSignature(pk,d,a,s,challenge) ? "verified" : "unverified");
