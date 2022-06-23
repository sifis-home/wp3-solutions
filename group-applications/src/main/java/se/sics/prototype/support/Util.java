/*******************************************************************************
 * Copyright (c) 2022, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.prototype.support;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.junit.Assert;
import org.postgresql.core.Utils;

import com.upokecenter.cbor.CBORObject;
import se.sics.ace.Constants;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;

/**
 * Class to hold various utility methods.
 * 
 *
 */
public class Util {

	/**
	 * Compute a signature, using the same algorithm and private key used in the
	 * OSCORE group to join
	 * 
	 * @param privKey private key used to sign
	 * @param dataToSign content to sign
	 * @param countersignKeyCurve value of countersignKeyCurve as integer
	 * @return byte array with signature
	 * 
	 */
	public static byte[] computeSignature(PrivateKey privKey, byte[] dataToSign, int countersignKeyCurve) {

		Signature mySignature = null;
		byte[] clientSignature = null;

		try {
			if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
				mySignature = Signature.getInstance("SHA256withECDSA");
			else if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
				mySignature = Signature.getInstance("NonewithEdDSA", "EdDSA");
			else {
				// At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are
				// supported
				Assert.fail("Unsupported signature algorithm");
			}

		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
			Assert.fail("Unsupported signature algorithm");
		} catch (NoSuchProviderException e) {
			System.out.println(e.getMessage());
			Assert.fail("Unsopported security provider for signature computing");
		}

		try {
			if (mySignature != null)
				mySignature.initSign(privKey);
			else
				Assert.fail("Signature algorithm has not been initialized");
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
			Assert.fail("Invalid key excpetion - Invalid private key");
		}

		try {
			if (mySignature != null) {
				mySignature.update(dataToSign);
				clientSignature = mySignature.sign();
			}
		} catch (SignatureException e) {
			System.out.println(e.getMessage());
			Assert.fail("Failed signature computation");
		}

		return clientSignature;

	}

	/**
	 * Parse a received Group OSCORE join response and print the information in
	 * it.
	 * 
	 * @param joinResponse the join response
	 */
	public static void printJoinResponse(CBORObject joinResponse) {

		// Parse the join response generally

		System.out.println();
		System.out.println("Join response contents: ");

		System.out.print("KID: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KID)));

		System.out.print("KEY: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KEY)));

		System.out.print("PROFILE: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PROFILE)));

		System.out.print("EXP: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.EXP)));

		System.out.print("PUB_KEYS: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)));

		System.out.print("NUM: ");
		System.out.println(joinResponse.get(CBORObject.FromObject(Constants.NUM)));

		// Parse the KEY parameter

		CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

		System.out.println();
		System.out.println("KEY map contents: ");

		System.out.print("ms: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ms)));

		System.out.print("id: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.id)));

		System.out.print("hkdf: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.hkdf)));

		System.out.print("alg: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.alg)));

		System.out.print("salt: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.salt)));

		System.out.print("contextId: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.contextId)));

		System.out.print("ecdh_alg: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));

		System.out.print("ecdh_params: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));

		System.out.print("group_SenderID: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));

		System.out.print("pub_key_enc: ");
		System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.pub_key_enc)));

		// Parse the PUB_KEYS parameter

		System.out.println();
		System.out.println("PUB_KEYS contents: ");

		if (joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS))) {
			CBORObject coseKeySetArray = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS));

			for (int i = 0; i < coseKeySetArray.size(); i++) {

				CBORObject key_param = coseKeySetArray.get(i);

				System.out.println("Key " + i + ": " + key_param.toString());
			}
		}
	}

	/**
	 * Generate a Group OSCORE Security context from material received in a Join
	 * response.
	 * 
	 * @param joinResponse holds the information in the Join response
	 * @param clientKey key of peer joining the group
	 * 
	 * @return a Group OSCORE context generated from the Join response
	 */
	public static GroupCtx generateGroupOSCOREContext(CBORObject joinResponse, MultiKey clientKey) {

		int replayWindow = 32;
		byte[] gmPubKey = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString();

		// Parse the KEY parameter

		CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));

		byte[] ms = keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ms)).GetByteString();
		byte[] salt = keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.salt)).GetByteString();
		byte[] sid = keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID))
				.GetByteString();
		byte[] idContext = keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.contextId))
				.GetByteString();

		AlgorithmID alg = null;
		AlgorithmID kdf = null;
		AlgorithmID algCountersign = null;
		try {
			alg = AlgorithmID
					.FromCBOR(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.alg)));
			kdf = AlgorithmID
					.FromCBOR(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.hkdf)));
			algCountersign = AlgorithmID
					.FromCBOR(keyMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
		} catch (CoseException e1) {
			System.err.println("Failed to parse crypto params in join response: " + e1.toString());
		}

		GroupCtx commonCtx = new GroupCtx(ms, salt, alg, kdf, idContext, algCountersign, gmPubKey);

		try {
			System.out.println("Adding Sender CTX for: " + Utils.toHexString(sid) + " "
					+ clientKey.getCoseKey().AsCBOR().toString());
			commonCtx.addSenderCtxCcs(sid, clientKey);
		} catch (OSException e) {
			System.err.println("Error: Failed to build Sender CTX for client.");
			e.printStackTrace();
		}

		// Parse public keys and add recipient contexts
		if (joinResponse.ContainsKey(CBORObject.FromObject(Constants.PUB_KEYS))) {
			CBORObject coseKeySetArray = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS));

			for (int i = 0; i < coseKeySetArray.size(); i++) {

				CBORObject key_param = coseKeySetArray.get(i);

				CBORObject parsedKey = CBORObject.DecodeFromBytes(key_param.GetByteString());

				byte[] recipientId = joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(i)
						.GetByteString();
				MultiKey recipientKey = new MultiKey(key_param.GetByteString());
				try {
					System.out.println(
							"Adding Recipient CTX for: " + Utils.toHexString(recipientId) + " " + parsedKey.toString());
					commonCtx.addRecipientCtxCcs(recipientId, replayWindow, recipientKey);
				} catch (OSException e) {
					System.err.println("Error: Failed to add Recipient CTX");
					e.printStackTrace();
				}
			}
		}

		return commonCtx;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Curve25519. Will not fill
	 * the Java private and public key in the COSE key. So can only be used for
	 * shared secret calculation.
	 * 
	 * @param privateKey the private key bytes (private scalar here)
	 * @param publicKey the public key bytes FIXME: Remove?
	 * @return a OneKey representing the input material
	 */
	static OneKey buildCurve25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		OneKey key = new OneKey();

		key.add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));

		if (privateKey != null)
			key.add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Generate a CCS using a particular algorithm and subject name. Prints the
	 * CCS and associated private key as hex output.
	 * 
	 * @param alg key algorithm
	 * @param subjectName subject name
	 */
	public static void generateCcs(AlgorithmID alg, String subjectName) {

		System.out.println("Generating key for subject name: " + subjectName);

		OneKey key = null;
		try {
			key = OneKey.generateKey(alg);
		} catch (CoseException e) {
			System.err.println("Failed to build COSE key: " + e.toString());
		}

		String privateKey = "";
		if (alg == AlgorithmID.ECDSA_256 || alg == AlgorithmID.ECDSA_384 || alg == AlgorithmID.ECDSA_512) {
			privateKey = StringUtil.byteArray2Hex(key.get(KeyKeys.EC2_D).GetByteString());
		} else if (alg == AlgorithmID.EDDSA) {
			privateKey = StringUtil.byteArray2Hex(key.get(KeyKeys.OKP_D).GetByteString());
		} else {
			System.err.println("Unknown algorithm");
			return;
		}

		System.out.println("Private key: " + privateKey);

		byte[] ccsBytes = AceUtil.oneKeyToCCS(key, subjectName);
		String ccs = StringUtil.byteArray2Hex(ccsBytes);

		System.out.println("CCS: " + ccs);
	}

}
