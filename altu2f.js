/**
 *
 * altU2F is a software implementation of the U2F authenticator.
 *
 * This implementation is primarly useful on devices that do not support regular U2F authenticator.
 *
 * Include this script on the site executing the u2f.sign and u2f.register
 *
 * TODO: Introduce possibilitiy for keyHandle encryption/decryption
 * FIXME: check if the provided appId is allowed
 * TODO: Store encrypted private key in the keyhandle, allow recovering via a recovery key
 *
 */

var URLSafeBase64 = require('urlsafe-base64');
var Buffer = require('buffer').Buffer;
var jsrsasign = require("jsrsasign");

window.AltU2F = {};

window.AltU2F.init = function(parameters) {

	var parent = this;

	this.m = {

		getStoredKeys : function() {
			var storedKeysRaw = localStorage.getItem("keys");
			var storedKeys;

			if (storedKeysRaw && storedKeysRaw != '[]') {
				storedKeys = JSON.parse(storedKeysRaw);
			} else {
				storedKeys = {};
			}

			return storedKeys;
		},

		storeKeys : function(keys) {
			localStorage.setItem("keys", JSON.stringify(keys));
		},

		/**
		 * Send the data from u2f.sign to this method.
		 *
		 * This method send the data to a server which allows picking up the
		 * data by someone else who knows the keyhandle
		 */
		onStartSign : function(caller) {
			caller.userPresenceConfirmed();
		},

		onFinishSign : function() {
			console.log("confirmed user presence and finished signing");
		},

		/**
		 * Receives the data from u2f.register
		 *
		 * @param registerRequest
		 * @param callbackm
		 */
		onStartRegister : function(caller) {
			caller.userPresenceConfirmed();

		},

		onFinishRegister : function() {
			console.log("Finished U2F registration");
		},

		/**
		 * Retrieve the attestation key and certificate.
		 */
		getAttestationKeys : function() {

			return {
				certificateAttestation : "	-----BEGIN CERTIFICATE-----\n\
												MIICAzCCAaegAwIBAgIEA/ZKJDAMBggqhkjOPQQDAgUAMHYxCzAJBgNVBAYTAk5M\n\
												MRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQHEwlIaWx2ZXJzdW0xEDAO\n\
												BgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xFzAVBgNVBAMTDkFyaWUg\n\
												VGltbWVybWFuMB4XDTE2MTAwODA3MzE0MVoXDTE3MTAwODA3MzE0MVowdjELMAkG\n\
												A1UEBhMCTkwxFjAUBgNVBAgTDU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcTCUhpbHZl\n\
												cnN1bTEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEXMBUGA1UE\n\
												AxMOQXJpZSBUaW1tZXJtYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR3XnoU\n\
												InoH/EXwbeyavDVBuht6riOwqeZuVADULc4jRJL23KUlFgC8MXg6Gb5TzBMDUcAS\n\
												DuOTZdiD2MPH+mOqoyEwHzAdBgNVHQ4EFgQUE3YVJs0EILDr9I8GmF4t7fw8cpEw\n\
												DAYIKoZIzj0EAwIFAANIADBFAiAMmauRfap8SiJcwkZFYefEoANP1jCpRjH/xFa6\n\
												rfAxiwIhAKOnZd3OsAYnhl2AOgmbN19W3g220nIR5qyiW7/JePiH\n\
												-----END CERTIFICATE-----\n",

				privateKeyAttestation : "	-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
												MIHVMEAGCSqGSIb3DQEFDTAzMBsGCSqGSIb3DQEFDDAOBAgmMKadDzyZXQICCAAw\n\
												FAYIKoZIhvcNAwcECAqZrbQJvXnaBIGQs7LjOCIL6019oNOlgEJAwYguUHPb5xYK\n\
												wmWaiNrZvtV94rnrQjl6HW7KwLyRhx09Q9KHWCZi4i220c9l+kzfhSIJP4gBNsXt\n\
												hGS7/iE8nc4VZhogSZcVo6e+LCVgF0dyXYsxBTNSZ6eXl4So7CtXeCe/GvE9xPXR\n\
												009uZC1JioHMY15z5N1LVDK8vXUCAU7Q\n\
												-----END ENCRYPTED PRIVATE KEY-----"
			}

		},

	}

	/**
	 * Set the signature
	 */
	this.sign = function(appId, challenge, regKeys, callback) {

		this.appId = appId;
		this.challenge = challenge;
		this.regKeys = regKeys;
		this.callback = callback;

		this.userPresenceConfirmed = function() {

			var keys = parent.m.getStoredKeys();

			// First retrieve the private key based on the provided keyhandle
			var keyHandle = null;

			for(k in this.regKeys){
				if(keys[regKeys[k].keyHandle]){
					keyHandle = regKeys[k].keyHandle;
				}
			}

			//TODO: throw exception if no key
			var key = keys[keyHandle];

			// Increase the counter to prevent replay attacks
			var counter = keys[keyHandle].counter++;

			parent.m.storeKeys(keys);

			// Initialze signing
			var sig = new jsrsasign.KJUR.crypto.Signature({
				"alg" : 'SHA256withECDSA'
			});

			sig.initSign({
				'ecprvhex' : key.privateKey,
				'eccurvename' : 'secp256r1'
			});

			var clientData = {
				"typ" : "navigator.id.getAssertion",
				"challenge" : this.challenge,
				"origin" : parent.getOrigin()
			};

			var clientDataString = JSON.stringify(clientData);

			const clientDataStringBuffer = Buffer.from(clientDataString);

			const appIdHash = Buffer.from(parent.sha256(this.appId), 'hex');
			const reservedByte = Buffer.from('01', 'hex');
			const clientDataHash = Buffer.from(parent.sha256(clientDataString), 'hex');

			const counterBuffer = new Buffer(4);
			counterBuffer.writeUInt32BE(counter, 0);

			const signatureBytes = Buffer.concat([ appIdHash, reservedByte, counterBuffer, clientDataHash ]);

			sig.updateHex(signatureBytes.toString('hex'));

			var signatureE = sig.sign();

			const signature = new Buffer(signatureE, 'hex');
			const signatureData = Buffer.alloc(1 + 4 + signature.length);

			signatureData.writeUInt8(0x01, 0);
			signatureData.writeUInt32BE(counter, 1);
			signature.copy(signatureData, 5);

			// call the callback
			this.callback({
				clientData : URLSafeBase64.encode(clientDataStringBuffer),
				signatureData : URLSafeBase64.encode(signatureData),
				appId : this.appId,
				keyHandle : keyHandle,
			});

			parent.m.onFinishSign();

		}

		parent.m.onStartSign(this);

	};

	/**
	 * registeredKeys is ignored
	 * Returns a registrationResponse as defined in
	 * https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-javascript-api.html#idl-def-RegisterResponse
	 *
	 * @param registerRequest
	 * @returns
	 */
	this.register = function(appId, registerRequests, registeredKeys, callback) {

		this.registerRequest = registerRequests[0];
		this.callback = callback;

		/**
		 * This function should be called after the user presence has been confirmed, i.e. after pressing a button or entering a pincode
		 */
		this.userPresenceConfirmed = function() {

			// # Load the attestation certificate and the related private key
			var certificate = new jsrsasign.X509();
			certificate.readCertPEM(parent.m.getAttestationKeys().certificateAttestation);
			var decryptedPrivateKey = jsrsasign.KEYUTIL.getKey(parent.m.getAttestationKeys().privateKeyAttestation, "password");

			// # Generate the user public and private keys
			var ec = new jsrsasign.KJUR.crypto.ECDSA({
				"curve" : 'secp256r1'
			});

			var keypair = ec.generateKeyPairHex();

			// The keyHandle is stored at the server and should be used to
			// retrieve the correct private key for signing signRequests
			// FIXME: generate dynamically
			var keyHandle = 'aaaa';

			var keys = parent.m.getStoredKeys();

			// Store the generated keys
			keys[keyHandle] = {
				privateKey : keypair.ecprvhex,
				publicKey : keypair.ecpubhex,
				keyHandle : keyHandle,
				counter : 1,
			};

			parent.m.storeKeys(keys);

			var clientData = {
				"typ" : "navigator.id.finishEnrollment",
				"challenge" : this.registerRequest.challenge, // challenge
				// contains base64
				// encoded version.
				"origin" : parent.getOrigin()
			};

			var clientDataString = JSON.stringify(clientData);
			const clientDataStringBuffer = Buffer.from(clientDataString);

			// # Prepare the bytes over which a signature is calculated, using
			// the private key of the attestation certificate

			// A byte reserved for future use [1 byte] with the value 0x00. This
			// will evolve into a byte that will allow RPs to track known-good
			// applet version of U2F tokens from specific vendors.
			const reservedByte0 = Buffer.from('00', 'hex');

			// The application parameter [32 bytes] from the registration
			// request message
			const appIdHash = Buffer.from(parent.sha256(this.registerRequest.appId), 'hex');

			// The hash of the client data, containing the challenge
			const clientDataHash = Buffer.from(parent.sha256(clientDataString), 'hex');

			// The size of the keyhandle
			const keyHandleBuffer = Buffer.from(keyHandle, 'base64');

			// The generated public key
			const userPublicKey = Buffer.from(keys[keyHandle].publicKey, 'hex');

			// /Combine all signature bytes
			const signatureBytes = Buffer.concat([ reservedByte0, appIdHash, clientDataHash, keyHandleBuffer, userPublicKey ]);

			var sig = new jsrsasign.KJUR.crypto.Signature({
				"alg" : 'SHA256withECDSA'
			});

			sig.init(decryptedPrivateKey);

			sig.updateHex(signatureBytes.toString('hex'));
			var signature = sig.sign();

			// # Now prepare the registrationData, which includes the generated
			// signature

			// A reserved byte [1 byte], which for legacy reasons has the value
			// 0x05.
			const reservedByte5 = Buffer.from('05', 'hex');

			// The length of the keyHandle, which is variable
			const keyHandleBufferLength = new Buffer(1);
			keyHandleBufferLength.writeInt8(keyHandleBuffer.length);

			const attestationCertificateBuffer = Buffer.from(certificate.hex, 'hex');
			const signatureBuffer = Buffer.from(signature, 'hex');

			// Now create the complete registrationData
			const registrationData = Buffer.concat([ reservedByte5, userPublicKey, keyHandleBufferLength, keyHandleBuffer, attestationCertificateBuffer, signatureBuffer ]);

			// Return the registration data
			var registrationResponse = {
				version : "U2F_V2",
				appId: this.registerRequest.appId,
				challenge: this.registerRequest.challenge,
				clientData : URLSafeBase64.encode(clientDataStringBuffer),
				registrationData : URLSafeBase64.encode(registrationData),
			};

			this.callback(registrationResponse);

			parent.m.onFinishRegister();

		};

		parent.m.onStartRegister(this);

	}

	/**
	 * Caculates the sha256 hash for a provided string
	 */
	this.sha256 = function(input) {

		var md = new jsrsasign.KJUR.crypto.MessageDigest({
			alg : "sha256",
			prov : "cryptojs"
		});
		md.updateString(input)
		return md.digest()

	};

	/**
	 * Retrieves the "origin", as defined in ...
	 */
	this.getOrigin = function() {
		return location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '');
	};

	if (parameters) {
		for ( var attrname in parameters) {
			this.m[attrname] = parameters[attrname];
		}
	}

	// if u2f is not supported, create empty functions
	if (!window.u2f) {
		window.u2f = function() {

		}

		window.u2f.sign = function() {

		}

		window.u2f.register = function() {

		}
	}

	(function(proxied) {
		window.u2f.sign = function() {

			parent.sign(arguments[0], arguments[1], arguments[2], arguments[3]);

			return proxied.apply(this, arguments);
		};
	})(window.u2f.sign);

	(function(proxied) {
		window.u2f.register = function() {

			parent.register(arguments[0], arguments[1], arguments[2], arguments[3]);

			return proxied.apply(this, arguments);
		};
	})(window.u2f.register);

}
