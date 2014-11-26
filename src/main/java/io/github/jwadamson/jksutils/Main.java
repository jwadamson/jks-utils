package io.github.jwadamson.jksutils;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.Parser;
import org.apache.commons.cli.PosixParser;

public final class Main {

    //*************************************************************************
    // CLASS
    //*************************************************************************

    static private final Options OPTS = new Options();
    static {
        OPTS.addOption(new Option("h", "help", false, "Print this message"));
        OPTS.addOption(new Option("v", "verbose", false, "Verbose mode"));
//        OPTS.addOption(new Option("q", "quiet", false, "Quiet mode"));
        OPTS.addOption(new Option("n", "dry", false, "Show what would have been done, but do not save any changes."));
        OPTS.addOption(new Option("i", "interactive", false, "Prompt for confirmation before adding any certificate"));
        OPTS.addOption(new Option(null, "root", false, "Import the root ca instead of the leaf certificate."));
        OPTS.addOption(new Option("f", "force", false, "Import certificate even if chain is already trusted."));
        Option alias = new Option(null, "alias", true, "The alias to use for imported cert.");
        alias.setArgName("<alias>");
        OPTS.addOption(alias);
    }

    static public void usage() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("url keystorefile [keystorepassword]", OPTS);
    }

    static public void main(String[] args)
    throws MalformedURLException, GeneralSecurityException, IOException {
        boolean verbose = false;
//        boolean quiet = false;
        boolean dryRun = false;
        boolean interactive = false;
        boolean importRoot = false;
        boolean force = false;
        String certAlias = null;

        Parser parser = new PosixParser();
        try {
            CommandLine line = parser.parse(OPTS, args, true);
            @SuppressWarnings("unchecked")
            List<String> arguments = line.getArgList();
            boolean showHelp = line.hasOption('h');
            if (showHelp) {
                usage();
                System.exit(0);
            }

            verbose = line.hasOption('v');
//            quiet = line.hasOption('q');
            dryRun = line.hasOption('n');
            interactive = line.hasOption('i');
            importRoot = line.hasOption("root");
            force = line.hasOption('f');
            certAlias = line.getOptionValue("alias");
            if (arguments.size() < 2) {
                usage();
                System.exit(1);
            }
            String urlString = arguments.get(0);
            File keystoreFile = new File(arguments.get(1));
            char[] keystorePass = "changeit".toCharArray();
            if (arguments.size() > 2) {
                keystorePass = arguments.get(2).toCharArray();
            }

            URL url = new URL(urlString);
            String host = url.getHost();
            int port = url.getPort();
            if (port == -1) {
                port = url.getDefaultPort();
            }

            RemoteJksImport util = new RemoteJksImport();

            X509Certificate[] certificateChain = util.getUntrustedCertificateChain(host, port, keystoreFile, keystorePass, force);
            if (certificateChain != null && certificateChain.length > 0) {
                X509Certificate cert;
                if (importRoot) {
                    cert = certificateChain[certificateChain.length - 1];
                }
                else {
                    cert = certificateChain[0];
                }

                if (certAlias == null || certAlias.length() == 0) {
                    certAlias = util.getName(cert.getSubjectX500Principal());
                }
                if (certAlias.equalsIgnoreCase("localhost")) {
                    certAlias = ""+host+":"+port;
                }
                util.println("Importing%s certificate from %s:%s into keystore %s as %s",
                        importRoot ? " root": "",host, port, keystoreFile, certAlias);

                boolean doImport = false;
                Console cons = System.console();
                if (dryRun) {
                    doImport = false;
                    util.println("Dry run, would have added cert to keystore");
                }
                else if (interactive) {
                    if (cons == null) {
                        util.println("Interactive but running without console, treating as dry run");
                        doImport = false;
                    }
                    else {
                        String ans = cons.readLine("Cerificate not trusted, should it be imported? [y,N] ");
                        doImport = ans.regionMatches(true, 0, "y", 0, 1);
                    }
                }
                else {
                    doImport = true;
                }

                if (doImport) {
                    util.addCert(keystoreFile, keystorePass, cert, certAlias);
                    util.println("Certificate successfully imported into %s", keystoreFile);
                }
            }
        }
        catch (ParseException pe) {
            System.err.println("Error: " + pe.getMessage());
            usage();
            System.exit(1);
        }
        catch (Exception e) {
            System.err.println(String.valueOf(e));
            if (verbose) {
                e.printStackTrace(System.err);
            }
            System.exit(1);
        }
    }

    //*************************************************************************
    // INSTANCE
    //*************************************************************************

    private Main() {
    }
}
