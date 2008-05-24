/*PREAMBLE*/

package net.sf.jaasrimap;

import java.util.HashMap;
import java.util.Map;

/**
 *
 *
 * Instances of this class are thread safe.
 */
public class LoginCache {
	private final Map cache = new HashMap();
	
	public synchronized boolean check(LoginCacheKey key) {
		Long expires = (Long)cache.get(key);
		if (expires == null) {
			return false;
		} else if (expires.longValue() < System.currentTimeMillis()) {
			cache.remove(key);
			return false;
		} else {
			return true;
		}
	}
	
	public synchronized void add(LoginCacheKey key, int ttl) {
		cache.put(key, new Long(System.currentTimeMillis() + 1000*ttl));
	}
}
