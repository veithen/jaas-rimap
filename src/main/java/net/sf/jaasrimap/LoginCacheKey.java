/*PREAMBLE*/

package net.sf.jaasrimap;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class LoginCacheKey {
	private final String realm;
	private final String user;
	private final byte[] passwordHash;
	
	public LoginCacheKey(String realm, String user, char[] password) {
		this.realm = realm;
		this.user = user;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			for (int i=0; i<password.length; i++) {
				char c = password[i];
				md.update((byte)c);
				md.update((byte)(c >> 8));
			}
			passwordHash = md.digest();
		}
		catch (NoSuchAlgorithmException ex) {
			throw new Error(ex);
		}
	}

	public boolean equals(Object _obj) {
		if (_obj instanceof LoginCacheKey) {
			LoginCacheKey obj = (LoginCacheKey)_obj;
			return realm.equals(obj.realm) && user.equals(obj.user) && Arrays.equals(passwordHash, obj.passwordHash);
		} else {
			return false;
		}
	}

	public int hashCode() {
		int result = realm.hashCode();
		result = 37*result + user.hashCode();
		for (int i=0; i<passwordHash.length; i++) {
			result = 37*result + passwordHash[i];
		}
		return result;
	}
}
