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

public class CShow extends ASingleEntry
{
    protected String getMissingArgumentError()
    { return "show needs one argument, an entry"; }

    protected void handle
        (CConfig config, CDatabase db, char[] pw, CDatabase.Entry e)
        throws JSONException
    {
        CConsole.message("   id: "+e.getId());
        CConsole.message(" name: "+e.getUserName());

        // Copy to clipboard if possible, otherwise to terminal.
        boolean copied = false;
        try {
            Toolkit tk = Toolkit.getDefaultToolkit();
            if (tk != null) {
                Clipboard clip = tk.getSystemClipboard();
                if (clip != null) {
                    StringSelection ss =
                        new StringSelection(e.getPassword());
                    ClipboardOwner nop = new ClipboardOwner() {
                            public void lostOwnership
                                (Clipboard c, Transferable t)
                            { /* do nothing */ }
                        };
                    clip.setContents(ss, nop);
                    copied = true;
                    CConsole.message("Password copied to clipboard");
                    CConsole.message("Will delete after 30 seconds...");
                    try { Thread.sleep(30*1000); }
                    catch (InterruptedException ie) {}
                    ss = new StringSelection("");
                    clip.setContents(ss, nop);
                    CConsole.message("...deleted from clipboard");
                }
            }
        }
        catch (Throwable ign) {}
        if (!copied) {
            CConsole.message(" pass: "+e.getPassword());
        }
    }
}
