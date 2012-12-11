package org.pwmgr;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CConsole;
import org.pwmgr.command.CInit;
import org.pwmgr.command.CRemaster;
import org.pwmgr.command.CAdd;
import org.pwmgr.command.CShow;
import org.pwmgr.command.CList;
import org.pwmgr.command.CRemove;
import org.pwmgr.command.CEdit;
import org.pwmgr.command.ASingleEntry;

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

        char[] pw = CConsole.readPassword("Passphrase", false);
        if (pw == null) { return; }

        try {
            switch (config.getCommand()) {
            case ADD: CAdd.execute(config, pw); break;
            case LIST: CList.execute(config, pw); break;
            case REMASTER: CRemaster.execute(config, pw); break;

            case SHOW:
                ASingleEntry.execute(config, pw, new CShow()); break;
            case REMOVE:
                ASingleEntry.execute(config, pw, new CRemove()); break;
            case EDIT:
                ASingleEntry.execute(config, pw, new CEdit()); break;
            default:
                throw new IllegalStateException
                    ("Missing command "+config.getCommand());
            }
        }
        finally {
            Arrays.fill(pw, '.');
        }
    }
}
