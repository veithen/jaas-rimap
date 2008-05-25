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

import gnu.inet.imap.IMAPConstants;
import gnu.inet.imap.IMAPResponse;
import gnu.inet.imap.IMAPResponseTokenizer;
import gnu.inet.util.CRLFOutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

public class RIMAPLoginModule extends AbstractLoginModule {
    private class IMAPConnection {
        private final static String TAG_PREFIX = "A";
        private final String[] protocols = { "TLSv1", "SSLv3" };
        
        private Socket socket;
        private CRLFOutputStream out;
        private IMAPResponseTokenizer in;
        private int tagIndex = 0;
        private boolean isPreauthenticated;
        private boolean isClosed = false;
        
        public IMAPConnection() throws IOException {
            socket = new Socket();
            InetSocketAddress address = new InetSocketAddress(host, port);
            if (connecttimeout > 0) {
                socket.connect(address, connecttimeout);
            } else {
                socket.connect(address);
            }
        }
        
        public void setOptions() throws IOException {
            if (timeout > 0) {
                socket.setSoTimeout(timeout);
            }
        }
        
        public void processGreeting() throws IOException {
            wrapStreams();
            if (debug) { log("Reading server greeting"); }
            IMAPResponse greeting = in.next();
            if (debug) { log("< " + greeting); }
            if (greeting.isTagged()) {
                throw new IOException("Expected untagged greeting from server"); // TODO: exception
            }
            String id = greeting.getID();
            if (id == IMAPConstants.OK) {
                isPreauthenticated = false;
            } else if (id == IMAPConstants.PREAUTH) {
                isPreauthenticated = true;
            } else if (id == IMAPConstants.BYE) {
                // TODO: close and set isClosed
                throw new IOException("Server closed connection immediatly"); // TODO: exception
            } else {
                throw new IOException("Expected untagged greeting from server"); // TODO: exception
            }
        }
        
        public boolean isPreauthenticated() { return isPreauthenticated; }
        public boolean isClosed() { return isClosed; }
        
        private void wrapStreams() throws IOException {
            if (out == null) {
                out = new CRLFOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            }
            if (in == null) {
                in = new IMAPResponseTokenizer(new BufferedInputStream(socket.getInputStream()));
            }
        }
        
        public void startSSL(TrustManager tm) throws IOException {
            if (debug) { log("Switching to SSL"); }
            SSLContext context;
            try {
                context = SSLContext.getInstance("TLS");
                context.init(null, tm == null ? null : new TrustManager[] { tm }, null);
            }
            catch (GeneralSecurityException ex) {
                throw new IOException("Failed to create SSL context (" + ex.getMessage() + ")");
            }
            SSLSocket ss = (SSLSocket)context.getSocketFactory().createSocket(socket, host, port, true);
            ss.setEnabledProtocols(protocols);
            ss.setUseClientMode(true);
            ss.startHandshake();
            socket = ss;
            out = null;
            in = null;
        }
        
        public IMAPResponse sendCommand(String command) throws IOException {
            wrapStreams();
            String tag = TAG_PREFIX + (++tagIndex);
            String taggedCommand = tag + " " + command;
            if (debug) { log("> " + taggedCommand); }
            out.write(taggedCommand);
            out.writeln();
            out.flush();
            boolean bye = false;
            while (true) {
                IMAPResponse response = in.next();
                if (debug) { log("< " + response); }
                if (response == null) {
                    throw new EOFException();
                }
                if (tag.equals(response.getTag())) {
                    if (bye) {
                        close();
                    }
                    return response;
                } else if (response.isUntagged()) {
                    if (response.getID() == IMAPConstants.BYE) {
                        bye = true;
                    }
                    // TODO: else
                } else {
                    throw new IOException(response.getText());  // TODO: exception
                }
            }
        }
        
        public void close() throws IOException {
            socket.close();
            isClosed = true;
        }
    }
    
    private final static LoginCache cache = new LoginCache();
    
    String host;
    private boolean usessl;
    int port;
    int connecttimeout;
    int timeout;
    private boolean usetls;
    private boolean validatecert;
    private int cachettl;
    
    private boolean loginSucceeded;
    private boolean commitSucceeded;
    private RIMAPHostPrincipal hostPrincipal;
    private RIMAPUserPrincipal userPrincipal;
    
    private final static String[] PROTOCOLS = { "imap", "imaps" };
    
    @Override
    protected void init(Map<String,?> sharedState, Map<String,?> options) {
        host = getOptionAsString(options, "host", "localhost");
        usessl = getOptionFromEnum(options, "protocol", PROTOCOLS, 0) == 1;
        port = getOptionAsInteger(options, "port", usessl ? 993 : 143);
        connecttimeout = getOptionAsInteger(options, "connecttimeout", 0);
        timeout = getOptionAsInteger(options, "timeout", 0);
        usetls = getOptionAsBoolean(options, "usetls", false);
        validatecert = getOptionAsBoolean(options, "validatecert", true);
        cachettl = getOptionAsInteger(options, "cachettl", 0);
        if (usessl && usetls) {
            if (debug) { log("Ignoring option 'usetls'"); }
            usetls = false;
        }
    }
    
    public boolean login() throws LoginException {
        if (callbackHandler == null) {
            throw new LoginException("This login module requires a callback handler");
        }
        
        String user;
        char[] password;
        
        {
            NameCallback nameCallback = new NameCallback("User: ");
            PasswordCallback passwordCallback = new PasswordCallback("Password: ", false);
            try {
                if (debug) { log("Invoking callbacks"); }
                callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
                user = nameCallback.getName();
                password = passwordCallback.getPassword();
            }
            catch (IOException ex) {
                throw new LoginException(ex.getMessage());
            }
            catch (UnsupportedCallbackException ex) {
                throw new LoginException(ex.getMessage());
            }
        }
        
        if (user == null || password == null) {
            throw new LoginException("Null user or password not allowed");
        }
        if (debug) { log("User: " + user); }
        
        LoginCacheKey key;
        if (cachettl == 0) {
            key = null;
        } else {
            key = new LoginCacheKey(host + ":" + port + ":" + usessl + ":" + usetls, user, password);
            if (cache.check(key)) {
                if (debug) { log("OK from login cache; not connecting to IMAP server"); }
                return success(user);
            }
        }
        
        X509TrustManager trustManager;
        if ((usessl || usetls) && !validatecert) {
            if (debug) { log("Using promiscuous trust manager"); }
            trustManager = new PromiscuousX509TrustManager();
        } else {
            trustManager = null;
        }
        
        IMAPConnection conn;
        try {
            conn = new IMAPConnection();
        }
        catch (IOException ex) {
            throw new LoginException("Unable to open connection to IMAP server");
        }
        
        // From here on we have to make sure that the connection is always closed, so we put the
        // rest of the code in a separate try block.
        try {
            conn.setOptions();
            if (usessl) {
                conn.startSSL(trustManager); // TODO: trust manager should be configurable
            }
            conn.processGreeting();
            if (conn.isClosed()) {
                throw new LoginException("Server closed connection immediatly (BYE greeting)");
            } else {
                // From here on we have to send a LOGOUT command to cleanly shut down the
                // connection (unless there is an I/O or protocol error)
                try {
                    IMAPResponse response;
                    if (usetls) {
                        response = conn.sendCommand(IMAPConstants.STARTTLS);
                        if (response.getID() == IMAPConstants.OK) {
                            conn.startSSL(trustManager); // TODO: trust manager should be configurable
                        } else {
                            // This usually means that TLS is not supported. Throw a LoginException,
                            // so that a LOGOUT command will be issued.
                            throw new LoginException("STARTTLS failed: " + response.getText());
                        }
                    }
                    // TODO: avoid using new String(char[]) here
                    response = conn.sendCommand(IMAPConstants.LOGIN + " \"" + user + "\" \"" + new String(password) + "\"");
                    if (response.getID() == IMAPConstants.OK) {
                        if (debug) { log("Login on server successful"); }
                        response = conn.sendCommand(IMAPConstants.LOGOUT);
                        if (response.getID() == IMAPConstants.OK) {
                            if (conn.isClosed()) {
                                // When we get here, everything is alright...
                                if (key != null) {
                                    cache.add(key, cachettl);
                                }
                                return success(user);
                            } else {
                                throw new IOException("Connection not closed after LOGOUT");
                            }
                        } else {
                            // This is a protocol error; throw an IOException
                            throw new IOException("Unable to logout from server (" + response.getText() + ")");
                        }
                    } else {
                        if (debug) { log("Login on server failed"); }
                        loginSucceeded = false;
                        throw new FailedLoginException(response.getText());
                    }
                }
                catch (LoginException ex) {
                    try {
                        conn.sendCommand(IMAPConstants.LOGOUT);
                    }
                    catch (IOException ex2) {
                        // Do nothing here: we will rethrow the original exception, which is more
                        // interesting than any exception during logout.
                    }
                    throw ex;
                }
            }
        }
        catch (IOException ex) {
            if (debug) { log(ex); }
            throw new LoginException("I/O or protocol error while talking to IMAP server: " + ex.getMessage());
        }
        finally {
            if (!conn.isClosed()) {
                if (debug) { log("Force connection to be closed"); }
                try {
                    conn.close();
                }
                catch (IOException ex) {
                    // Do nothing here: we will only get here if an exception has been thrown, so we don't care
                    // about problems closing the connection.
                }
            }
        }
    }
    
    private boolean success(String user) {
        hostPrincipal = new RIMAPHostPrincipal(host);
        userPrincipal = new RIMAPUserPrincipal(user);
        loginSucceeded = true;
        return true;
    }

    public boolean commit() throws LoginException {
        if (loginSucceeded) {
            Set<Principal> principals = subject.getPrincipals();
            principals.add(hostPrincipal);
            principals.add(userPrincipal);
            clearState();
            return true;
        } else {
            return false;
        }
    }

    public boolean abort() throws LoginException {
        if (!loginSucceeded) {
            return false;
        } else if (!commitSucceeded) {
            // login succeeded but overall authentication failed
            clearState();
            return true;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
            return true;
        }
    }

    public boolean logout() throws LoginException {
        if (!subject.isReadOnly()) {
            Set<Principal> principals = subject.getPrincipals();
            principals.remove(hostPrincipal);
            principals.remove(userPrincipal);
        }
        clearState();
        return true;
    }
    
    private void clearState() {
        hostPrincipal = null;
        userPrincipal = null;
    }
}
