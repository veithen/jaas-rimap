/*PREAMBLE*/

package net.sf.jaasrimap;

import java.security.Principal;

public final class RIMAPHostPrincipal implements Principal {
	private final String name;
	
	public RIMAPHostPrincipal(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
	
	public int hashCode() {
		return name.hashCode();
	}

	public boolean equals(Object obj) {
		return obj instanceof RIMAPHostPrincipal && name.equals(((RIMAPHostPrincipal)obj).name);
	}

	public String toString() {
		return name;
	}
}
