package io.github.jwadamson.jksutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;


public class RemoteJksImport {


    //*************************************************************************
    // INSTANCE
    //*************************************************************************

    PrintStream out = System.out;

    public RemoteJksImport() {
    }

    /**
     * Retrieve the certificate chain from the given host+port if it is untrusted by the given trustStore.
     * @param the remote host
     * @param the remote port
     * @param the keystore file
     * @param keystorePassword the keystore password
     */
    X509Certificate[] getUntrustedCertificateChain(String host, int port, File ksFile, char[] keystorePassword, boolean force )
    throws GeneralSecurityException, IOException {
        X509Certificate[] resultChain = null;
        boolean trusted = false;

        KeyStore ks = readKeyStore(ksFile, keystorePassword);
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] defaultTrustManagers = tmf.getTrustManagers();
        assert defaultTrustManagers.length == 1;
        X509TrustManager defaultTrustManager = (X509TrustManager) defaultTrustManagers[0];

        // create a trust manager to capture the certificate chain
        CertifcateChainTrustManager tm = new CertifcateChainTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);

        // open connection in order to capture certificate chain
        println("Opening connection to %s:%s...", host, port);
        SSLSocketFactory factory = context.getSocketFactory();
        try {
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.setSoTimeout(10000);
            println("Connecting");
            socket.connect(new InetSocketAddress(host, port), 10000);
            println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            trusted = true;
        }
        catch (SSLException e) {
            // most likely:
            //  un-trusted cert
            //  no trust-anchors in keystore
            //  could not negotiate secure protocol/cipher
        }
        catch (Exception e) {
            println(e.toString());
            throw new RuntimeException(e);
        }
        finally {
            // check chain regardless of if there was an SSL exception
            resultChain = tm.getResultChain();
            if (resultChain != null) {
                println("chain-length=%s", resultChain.length);
                for (X509Certificate cert : resultChain) {
                    println("\tcertificate %s issued by %s",
                            cert.getSubjectX500Principal().getName(),
                            cert.getIssuerX500Principal().getName());
                }
            }
        }

        if (resultChain == null) {
            println("Could not obtain certificate chain from %s:%s", host, port);
            return null;
        }
        else if (trusted) {
            println();
            println("No errors, certificate chain is already trusted");
            if (force) {
                println("\tForce addition of chain");
                return resultChain;
            }
            return null;
        }
        else {
            println();
            println("Certificate chain is not currently trusted");
            return resultChain;
        }
    }

    void addCert(File keyFile, char[] keystorePassword, X509Certificate cert)
    throws IOException, GeneralSecurityException {
        addCert(keyFile, keystorePassword, cert, null);
    }

    /**
     * Add the given certificate to the given keystore file
     * @param keyFile the keystore file
     * @param keystorePassword the keystore password
     * @param certChain the chain to trust
     * @throws FileNotFoundException
     */
    void addCert(File keyFile, char[] keystorePassword, X509Certificate cert, String alias)
    throws IOException, GeneralSecurityException {
        KeyStore ks = readKeyStore(keyFile, keystorePassword);
        addCert(ks, cert, alias);
        FileOutputStream fos = new FileOutputStream(keyFile);
        ks.store(fos, keystorePassword);
        fos.close();
    }

    void addCert(KeyStore ks, X509Certificate cert, String alias)
    throws IOException, GeneralSecurityException {
        String issuer = getName(cert.getIssuerX500Principal());
        String subject = getName(cert.getSubjectX500Principal());
        if (alias == null || alias.length() == 0) {
            alias = subject;
        }
        println("Adding certificate '%s' for '%s' issued by '%s'", alias, subject, issuer);
        ks.setCertificateEntry(alias, cert);
    }

    /**
     * @param keyFile the keystore file
     * @param keystorePassword the keystore password
     * @return the keystore
     * @throws IOException
     * @throws GeneralSecurityException
     */
    KeyStore readKeyStore(File keyFile, char[] keystorePassword)
    throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("JKS");
        if (keyFile.isFile()) {
            InputStream in = new FileInputStream(keyFile);
            ks.load(in, keystorePassword);
            in.close();
        }
        else {
           ks.load(null, keystorePassword);
        }
        return ks;
    }

    void println() {
        out.println();
    }

    void println(String msg, Object... args) {
        if (args.length == 0) {
            out.println(msg);
        }
        else {
            out.println(String.format(msg, args));
        }
    }

    String getName(X500Principal principal) {
        String result = principal.getName();
        try {
            LdapName ldapDN = new LdapName(result);
            for(Rdn rdn: ldapDN.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    result = String.valueOf(rdn.getValue());
                }
            }
        }
        catch (InvalidNameException e) {
            // fall back to result.
        }

        return result;
    }
}