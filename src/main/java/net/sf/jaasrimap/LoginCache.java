/**
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.sf.jaasrimap;

import java.util.HashMap;
import java.util.Map;

/**
 *
 *
 * Instances of this class are thread safe.
 */
public class LoginCache {
    private final Map<LoginCacheKey,Long> cache = new HashMap<LoginCacheKey,Long>();
    
    public synchronized boolean check(LoginCacheKey key) {
        Long expires = cache.get(key);
        if (expires == null) {
            return false;
        } else if (expires < System.currentTimeMillis()) {
            cache.remove(key);
            return false;
        } else {
            return true;
        }
    }
    
    public synchronized void add(LoginCacheKey key, int ttl) {
        cache.put(key, System.currentTimeMillis() + 1000*ttl);
    }
}
