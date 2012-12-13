package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CPGPUtils;
import org.pwmgr.util.CDatabase;

import org.jsonjava.JSONException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.security.SecureRandom;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.HeadlessException;

public class CList
    implements ICommand
{
    public boolean checkArgs(CConfig config)
    {
        List<String> args = config.getArgs();
        if (args != null) {
            switch (args.size()) {
            case 0: break;
            case 1: break;
            default:
                CConsole.error("list takes only one argument, an entry");
                return false;
            }
        }
        return true;
    }

    public void execute(CConfig config, CDatabase db, char[] pw)
        throws IOException, JSONException
    {
        String key = "";
        List<String> args = config.getArgs();
        if ((args != null) && (args.size() == 1)) {
            key = args.get(0);
        }

        // First look for exact matches, then inexact matches.
        CDatabase.Entry e = db.getById(key);
        if (e != null) {
            dumpEntry(e);
            return;
        }

        // Look for inexact matches.
        List<CDatabase.Entry> matches = db.looksLike(key);
        switch (matches.size()) {
        case 0:
            if (key.length() > 0) {
                CConsole.message("No matches found for '"+key+"'");
            }
            else {
                CConsole.message("No entries");
            }
            return;
        default:
            for (CDatabase.Entry me: matches) {
                dumpEntry(me);
                CConsole.message("");
            }
            return;
        }
    }

    private final static void dumpEntry(CDatabase.Entry e)
        throws JSONException
    {
        CConsole.message("   id: "+e.getId());
        CConsole.message(" name: "+e.getUserName());
    }
}
