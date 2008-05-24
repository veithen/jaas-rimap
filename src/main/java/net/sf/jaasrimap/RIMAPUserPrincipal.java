/*PREAMBLE*/

package net.sf.jaasrimap;

import java.security.Principal;

public final class RIMAPUserPrincipal implements Principal {
	private final String name;
	
	public RIMAPUserPrincipal(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
	
	public int hashCode() {
		return name.hashCode();
	}

	public boolean equals(Object obj) {
		return obj instanceof RIMAPUserPrincipal && name.equals(((RIMAPUserPrincipal)obj).name);
	}

	public String toString() {
		return name;
	}
}
