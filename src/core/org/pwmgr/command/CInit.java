package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import org.jsonjava.JSONException;

import java.io.File;
import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;

import java.util.Arrays;
import java.util.Date;

public class CInit
{
    public static void execute(CConfig config)
        throws IOException, JSONException
    {
        // Check for various files we'll be writing.
        String root = config.getArgOption(CConfig.ArgOption.PUBLIC);
        String ppath = config.getArgOption(CConfig.ArgOption.PRIVATE);

        boolean done = false;
        while (!done) {
            while (!validateDbRoot(root)) {
                root = CConsole.readString
                    ("Create password directory",
                     System.getProperty("user.home")+
                     File.separator+"pwmgr"+File.separator+"db");
            }

            ppath = config.getArgOption(CConfig.ArgOption.PRIVATE);
            while (!validatePrivatePath(ppath)) {
                ppath = CConsole.readString
                    ("Create secret key",
                     System.getProperty("user.home")+
                     File.separator+"pwmgr"+File.separator+"private.pgp");
            }

            CConsole.message("");
            CConsole.message("  Passwords under  "+root);
            CConsole.message("  Secret key file  "+ppath);
            CConsole.message("");
            done = CConsole.isYes("Proceed", true);
            if (!done) {
                root = null;
                ppath = null;
            }
        }

        // use provided paths to do the rest.
        config
            .setArgOption(CConfig.ArgOption.PUBLIC, root)
            .setArgOption(CConfig.ArgOption.PRIVATE, ppath);

        char[] pw = CConsole.readPassword("Master passphrase", true);
        if (pw == null) { return; }

        init(CDatabase.newDatabase(), config, pw);
    }

    final static void init(CDatabase db, CConfig config, char[] pw)
        throws IOException, JSONException
    {
        File rootf =
            new File(config.getArgOption(CConfig.ArgOption.PUBLIC));
        if (!rootf.isDirectory()) {
            if (!rootf.mkdirs()) {
                throw new IOException("Unable to create directory "+rootf);
            }
        }

        // Now generate keypair.
        CConsole.message("Generating keys. This may take a while...");
        PGPKeyRingGenerator krgen = CPGPUtils.generateKeyRingGenerator
            ("pwmgr", pw, 0x60);

        // Write out files.

        // Secret file is re-encrypted with master pass-phrase.
        // TBD: allow separate pass-phrases.
        PGPSecretKeyRing skr = krgen.generateSecretKeyRing();

        boolean ok = false;
        BufferedOutputStream out = null;
        File privfile = ensureParent
            (config.getArgOption(CConfig.ArgOption.PRIVATE));
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            skr.encode(bout);
            bout.close();

            out = new BufferedOutputStream(new FileOutputStream(privfile));
            CPGPUtils.symmetricEncryptAndSign
                (bout.toByteArray(), out, pw,
                 CPGPUtils.getSigningSecretKey(skr), pw,
                 "_CONSOLE", new Date());
            ok = true;
        }
        finally {
            if (out != null) {
                try { out.close(); } catch (Throwable ign){}
            }
            if (!ok) {
                Arrays.fill(pw, '.');
                privfile.delete();
            }
        }

        File pubfile = new File(rootf, CConfig.PUBKEY);
        PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();

        out = null;
        ok = false;
        try {
            out = new BufferedOutputStream(new FileOutputStream(pubfile));
            pkr.encode(out);
            ok = true;
        }
        finally {
            if (out != null) {
                try { out.close(); } catch (Throwable ign){}
            }
            if (!ok) {
                Arrays.fill(pw, '.');
                privfile.delete();
                pubfile.delete();
            }
        }

        ok = false;
        File pwdb = new File(rootf, CConfig.PWDB);
        try {
            db.save(config, skr, pw);
            ok = true;
            CConsole.message("Files generated successfully.");
            CConsole.message("  Passwords under: "+rootf);
            CConsole.message("  Private key file: "+privfile);
            CConsole.message("");
            CConsole.message("Remember to backup these files!");
        }
        finally {
            Arrays.fill(pw, '.');
            if (!ok) {
                privfile.delete();
                pubfile.delete();
                pwdb.delete();
            }
        }
    }

    private final static File ensureParent(String path)
    {
        File ret = new File(path);
        File p = ret.getParentFile();
        if ((p != null) && !(p.isDirectory())) {
            p.mkdirs();
        }
        return ret;
    }

    final static boolean validatePrivatePath(String p)
    {
        if (p == null) { return false; }
        File f = new File(p);

        // nothing here -- that's fine.
        if (!f.exists()) {
            return true;
        }
        CConsole.error("Will not overwrite existing file: "+p);
        return false;
    }

    final static boolean validateDbRoot(String rootS)
    {
        if (rootS == null) { return false; }
        File root = new File(rootS);

        // nothing here -- that's fine.
        if (!root.exists()) {
            return true;
        }
        // Check we don't have stuff underneath it already.
        if (!root.isDirectory()) {
            CConsole.error(rootS + " is not a directory");
            return false;
        }

        File pw = new File(root, CConfig.PWDB);
        if (pw.exists()) {
            CConsole.error("Will not overwrite existing file: "+pw);
            return false;
        }
        File pk = new File(root, CConfig.PUBKEY);
        if (pk.exists()) {
            CConsole.error("Will not overwrite existing file: "+pk);
            return false;
        }
        return true;
    }
}
