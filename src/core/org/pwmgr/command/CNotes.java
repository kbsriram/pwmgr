package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class CNotes extends ASingleEntry
{
    protected String getMissingArgumentError()
    { return "notes needs one argument, an entry"; }

    protected void handle
        (CConfig config, CDatabase db, char[] pw, CDatabase.Entry e)
        throws JSONException, IOException
    {
        CConsole.message("    id: "+e.getId());
        CConsole.message("  name: "+e.getUserName());
        String notes = e.getNotes();
        CConsole.message(" Notes:");
        CConsole.message(notes);
    }
}
