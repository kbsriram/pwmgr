package org.pwmgr;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.util.CDatabase;
import org.pwmgr.command.CInit;
import org.pwmgr.command.CRemaster;
import org.pwmgr.command.CAdd;
import org.pwmgr.command.CShow;
import org.pwmgr.command.CNotes;
import org.pwmgr.command.CList;
import org.pwmgr.command.CRemove;
import org.pwmgr.command.CEdit;
import org.pwmgr.command.ICommand;

import java.util.Arrays;

public class Main
{
    public static void main(String args[])
    {
        try { realMain(args); }
        catch (Throwable th) {
            th.printStackTrace();
        }
    }

    private static void realMain(String args[])
        throws Throwable
    {
        CConfig config = CConfig.getConfig(args);
        if (config == null) {
            return;
        }

        if (config.getCommand() == CConfig.Command.INIT) {
            CInit.execute(config);
            return;
        }

        // Everything else assumes a pre-existing config +
        // a master passphrase.
        if (!config.passBasicChecks()) {
            return;
        }

        // Map command to actual class.
        ICommand command;
        switch (config.getCommand()) {
        case ADD: command = new CAdd(); break;
        case LIST: command = new CList(); break;
        case REMASTER: command = new CRemaster(); break;
        case SHOW: command = new CShow(); break;
        case NOTES: command = new CNotes(); break;
        case REMOVE: command = new CRemove(); break;
        case EDIT: command = new CEdit(); break;
        default:
            throw new IllegalStateException
                ("Missing command "+config.getCommand());
        }

        // Check arguments.
        if (!command.checkArgs(config)) { return; }

        // Load database
        CDatabase db;
        char[] pw;
        do {
            pw = CConsole.readPassword("Passphrase", false);
            if (pw == null) { return; }
            try {
                db = CDatabase.load(config, pw);
                break;
            }
            catch (Throwable th) {
                CConsole.error("Wrong passphrase.");
                Arrays.fill(pw, '.');
            }
        } while (true);

        // Run command.

        try { command.execute(config, db, pw); }
        finally {
            Arrays.fill(pw, '.');
        }
    }
}
