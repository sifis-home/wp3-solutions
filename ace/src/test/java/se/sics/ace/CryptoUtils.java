package se.sics.ace;


public class CryptoUtils {

	public static byte[] hexToBytes(String input) {
		return net.i2p.crypto.eddsa.Utils.hexToBytes(input);
	}

}
