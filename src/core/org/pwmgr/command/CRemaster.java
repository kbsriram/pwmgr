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

public class CRemaster
{
    public static void execute(CConfig config, char[] pw)
        throws IOException, JSONException
    {
        CDatabase db = CDatabase.load(config, pw);
        String nroot;
        String nppath;
        char[] npw;

        do {
            npw = pw;

            do {
                nroot = CConsole.readString
                    ("New password directory", null);
                if (nroot == null) { return; }
            } while (!CInit.validateDbRoot(nroot));

            do {
                nppath = CConsole.readString
                    ("New private file path", null);
                if (nppath == null) { return; }
            } while (!CInit.validatePrivatePath(nppath));

            if (CConsole.isYes("Change master passphrase", false)) {
                npw = CConsole.readPassword("New master passphrase",true);
                if (npw == null) { return; }
            }

            CConsole.message("");
            CConsole.message("  New passwords under  : "+nroot);
            CConsole.message("  New private key file : "+nppath);
            if (npw != pw) {
                CConsole.message("              Password : <changed>");
            }
            CConsole.message("");
            if (CConsole.isYes("Proceed", true)) {
                break;
            }
        } while (true);

        // Create a new config
        CConfig nconfig = CConfig.getConfig
            (new String[] {
                "-"+CConfig.ArgOption.PUBLIC.getName(), nroot,
                "-"+CConfig.ArgOption.PRIVATE.getName(), nppath,
                CConfig.Command.INIT.getName()});
        if (nconfig == null) {
            throw new IllegalStateException("unexpected");
        }
        CInit.init(db, nconfig, npw);
    }
}
