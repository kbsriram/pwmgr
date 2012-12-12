package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.security.SecureRandom;

public class CAdd
{
    public static void execute(CConfig config, char[] pw)
        throws IOException, JSONException
    {
        CDatabase db = CDatabase.load(config, pw);

        String id;
        String name;
        String notes;
        char[] epassword;
        do {
            do {
                id = CConsole.readString("New id", null);
            } while ((id != null) && haveId(db, id));

            if (id == null) { return; }

            name = CConsole.readString("Username", null);
            if (name == null) { return; }

            if (CConsole.isYes("Autogenerate password", true)) {
                epassword = genPassword();
            }
            else {
                epassword = CConsole.readPassword
                    ("Password", true);
                if (epassword == null) { return; }
            }

            if (CConsole.isYes("Add notes", false)) {
                notes = CConsole.readMultiline("Notes");
                if (notes == null) { return; }
            }
            else {
                notes = "";
            }

            CConsole.message("");
            CConsole.message("About to add this entry:");
            CConsole.message("    id: "+id);
            CConsole.message("  name: "+name);
            if (notes.length() > 0) {
                CConsole.message(" Notes:");
                CConsole.message(notes);
            }
            CConsole.message("");
        } while (!CConsole.isYes("Proceed", false));

        add(config, db, id, name, notes, epassword, pw);
    }

    final static void add
        (CConfig config, CDatabase db,
         String id, String name, String notes,
         char[] epassword, char[] pw)
        throws JSONException, IOException
    {
        db.addEntry(id, name, notes, epassword);
        Arrays.fill(epassword, '.');
        db.save(config, pw);
        CConsole.message("Saved "+id);
    }

    private final static boolean haveId(CDatabase db, String id)
        throws JSONException
    {
        if (db.getById(id) != null) {
            CConsole.error("Already have '"+id+"' (use edit to update)");
            return true;
        }
        return false;
    }

    final static char[] genPassword()
    {
        SecureRandom sr = new SecureRandom();
        char[] ret = new char[PWLEN];

        for (int i=0; i<PWLEN; i++) {
            int idx = sr.nextInt(ALLOWED_LENGTH);
            ret[i] = ALLOWED.charAt(idx);
        }
        return ret;
    }

    private final static String ALLOWED =
        "abcdefghijklmnopqrstuvwxyz"+
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
        "0123456789"+
        "!@#^*(){}/=|.,-_";
    private final static int ALLOWED_LENGTH = ALLOWED.length();
    private final static int PWLEN = 18;
}
