package org.pwmgr.command;

import java.io.IOException;
import org.jsonjava.JSONException;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CDatabase;

public interface ICommand
{
    public boolean checkArgs(CConfig config);
    public void execute(CConfig config, CDatabase db, char[] pw)
        throws IOException, JSONException;
}
