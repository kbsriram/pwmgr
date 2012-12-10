package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.security.SecureRandom;

public class CEdit extends ASingleEntry
{
    protected String getMissingArgumentError()
    { return "show needs one argument, an entry"; }

    protected void handle
        (CConfig config, CDatabase db, char[] pw, CDatabase.Entry e)
        throws JSONException, IOException
    {
        CConsole.message("Editing: "+e.getId());
        CConsole.message("");

        boolean changed = false;
        boolean pwchanged = false;

        CConsole.message("Name: "+e.getUserName());
        if (CConsole.isYes("Change name", false)) {
            changed = true;
            String n = CConsole.readString("Update name", null);
            if (n == null) { return; }
            e.setUserName(n);
        }

        if (CConsole.isYes("Change password", false)) {
            changed = true;
            pwchanged = true;
            char epassword[] = null;
            if (CConsole.isYes("Autogenerate password", true)) {
                epassword = CAdd.genPassword();
            }
            else {
                epassword = CConsole.readPassword
                    ("Password", true);
                if (epassword == null) { return; }
            }
            e.setPassword(new String(epassword));
            Arrays.fill(epassword, '.');
        }

        String notes = e.getNotes();
        if (notes.length() > 0) {
            CConsole.message("Notes:");
            CConsole.message(notes);
        }
        if (CConsole.isYes("Change notes", false)) {
            changed = true;
            String n = CConsole.readMultiline("Notes");
            if (n == null) { return; }
            e.setNotes(n);
        }
        if (!changed) {
            CConsole.message("No changes");
            return;
        }

        CConsole.message("");
        CConsole.message("Modified "+e.getId());
        CConsole.message("  name: "+e.getUserName());
        if (pwchanged) {
            CConsole.message("passwd: <changed>");
        }
        notes = e.getNotes();
        if (notes.length() > 0) {
            CConsole.message(" Notes:");
            CConsole.message(notes);
        }
        CConsole.message("");

        if (CConsole.isYes("Proceed", false)) {
            db.save(config, pw);
            CConsole.message("Modified "+e.getId());
        }
        else {
            CConsole.message("No changes");
        }
    }
}
