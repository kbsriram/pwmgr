package org.pwmgr.command;

/**
 * Helper template class when a command wants exactly
 * one entry as an argument.
 */

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public abstract class ASingleEntry
{
    public static void execute(CConfig config, char[] pw, ASingleEntry h)
        throws IOException, JSONException
    {
        List<String> args = config.getArgs();
        if ((args == null) || (args.size() != 1)) {
            CConsole.error(h.getMissingArgumentError());
            return;
        }

        CDatabase db = CDatabase.load(config, pw);

        // First look for exact matches, then inexact matches.
        String id = args.get(0);
        CDatabase.Entry e = db.getById(id);
        if (e != null) {
            h.handle(config, db, pw, e);
            return;
        }

        // Look for inexact matches.
        List<CDatabase.Entry> matches = db.looksLike(id);
        switch (matches.size()) {
        case 0:
            CConsole.error("No id matches '"+id+"'");
            return;
        case 1:
            h.handle(config, db, pw, matches.get(0));
            return;
        default:
            CConsole.error("Multiple matches for '"+id+"'");
            for (CDatabase.Entry me: matches) {
                CConsole.message("   "+me.getId());
            }
            return;
        }
    }

    protected abstract void handle
        (CConfig config, CDatabase db, char[] pw, CDatabase.Entry e)
        throws JSONException, IOException;
    protected abstract String getMissingArgumentError();
}
