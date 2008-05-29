package net.sf.jaasrimap;

public enum Protocol {
    IMAP(false), IMAPS(true), IMAP_TLS(true);
    
    private final boolean secure;
    
    Protocol(boolean secure) {
        this.secure = secure;
    }

    public boolean isSecure() {
        return secure;
    }
}
