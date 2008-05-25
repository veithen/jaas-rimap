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

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

public abstract class AbstractLoginModule implements LoginModule {
	protected boolean debug;
	
	protected Subject subject;
	protected CallbackHandler callbackHandler;
	
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		debug = getOptionAsBoolean(options, "debug", false);
		if (debug) { log("debug = true"); }
		init(sharedState, options);
	}
	
	/**
	 *
	 * Because of a bug in LoginContext, this method should not be called initialize.
	 */
	protected abstract void init(Map sharedState, Map options);
	
	protected void log(String msg) {
		System.out.println(msg);
	}
	
	protected void log(Throwable ex) {
		ex.printStackTrace(System.out);
	}
	
	protected String getOptionAsString(Map options, String name, String defaultValue) {
		String value = (String)options.get(name);
		if (value == null) {
			if (debug) { log(name + " = " + defaultValue + " [default]"); }
			return defaultValue;
		} else {
			if (debug) { log(name + " = " + value); }
			return value;
		}
	}
	
	protected int getOptionFromEnum(Map options, String name, String[] values, int defaultValue) {
		String value = (String)options.get(name);
		if (value != null) {
			for (int i=0; i<values.length; i++) {
				if (values[i].equalsIgnoreCase(value)) {
					if (debug) { log(name + " = " + values[i]); }
					return i;
				}
			}
			if (debug) { log("Unknown value '" + value + "' for option '" + name + "', using default value"); }
		}
		if (debug) { log(name + " = " + values[defaultValue] + " [default]"); }
		return defaultValue;
	}
	
	protected boolean getOptionAsBoolean(Map options, String name, boolean defaultValue) {
		return getOptionFromEnum(options, name, new String[] { "false", "true" }, defaultValue ? 1 : 0) == 1;
	}
	
	protected int getOptionAsInteger(Map options, String name, int defaultValue) {
		String value = (String)options.get(name);
		if (value != null) {
			try {
				int result = Integer.parseInt(value);
				if (debug) { log(name + " = " + result); }
				return result;
			}
			catch (NumberFormatException ex) {
				if (debug) { log("Incorrect value '" + value + "' for option '" + name + "', using default value"); }
			}
		}
		if (debug) { log(name + " = " + defaultValue + " [default]"); }
		return defaultValue;
	}
}
