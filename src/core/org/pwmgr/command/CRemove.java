package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class CRemove extends ASingleEntry
{
    protected String getMissingArgumentError()
    { return "remove needs one argument, an entry"; }

    protected void handle
        (CConfig config, CDatabase db, char[] pw, CDatabase.Entry e)
        throws JSONException, IOException
    {
        CConsole.message("    id: "+e.getId());
        CConsole.message("  name: "+e.getUserName());
        String notes = e.getNotes();
        if (notes.length() > 0) {
            CConsole.message(" Notes:");
            CConsole.message(notes);
        }
        CConsole.message("");
        if (!CConsole.isYes("Remove this entry", false)) {
            return;
        }
        db.removeById(e.getId()).save(config, pw);
        CConsole.message("Removed "+e.getId());
    }
}
