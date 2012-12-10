package org.pwmgr.util;

import java.io.Console;

import java.util.Arrays;

public class CConsole
{
    public final static void trace(Throwable th)
    {
        th.printStackTrace();
    }

    public final static void error(String msg)
    {
        System.out.println();
        System.out.println("ERROR: "+msg);
    }

    public final static void message(String msg)
    { System.out.println(msg); }

    public final static boolean isYes(String prompt, boolean dflt)
    {
        Console cons;
        if ((cons = System.console()) == null) {
            throw new IllegalStateException("Unable to write to console");
        }
        String resp;
        while (true) {
            if (dflt) {
                resp = cons.readLine("%s? (Y/n) ", prompt);
            }
            else {
                resp = cons.readLine("%s? (y/N) ", prompt);
            }
            if (resp == null) { return false; }
            resp = resp.trim();
            if (resp.length() == 0) { return dflt; }
            if ("y".equalsIgnoreCase(resp)) { return true; }
            if ("n".equalsIgnoreCase(resp)) { return false; }
            System.out.println("Please type in y or n");
        }
    }

    public final static char[] readPassword(String prompt, boolean repeat)
    {
        char[] pw;
        boolean done = false;
        do {
            pw = readOnePassword(prompt);
            if (pw == null) { return null; }
            if (!repeat) { return pw; }
            char[] check = readOnePassword("Repeat");
            if (check == null) { return null; }
            if (check.length != pw.length) {
                error("Passwords don't match");
            }
            else {
                done = true;
                for (int i=0; i<pw.length; i++) {
                    if (pw[i] != check[i]) {
                        done = false;
                        error("Passwords don't match");
                        break;
                    }
                }
            }
            Arrays.fill(check, '.');
        } while (!done);

        return pw;
    }

    private final static char[] readOnePassword(String prompt)
    {
        Console cons;
        if ((cons = System.console()) == null) {
            throw new IllegalStateException("Unable to write to console");
        }
        while (true) {
            char[] ret = cons.readPassword("%s: ", prompt);
            if (ret == null) { return null; }
            if (ret.length == 0) { continue; }
            return ret;
        }
    }

    public final static String readMultiline(String prompt)
    {
        Console cons;
        if ((cons = System.console()) == null) {
            throw new IllegalStateException("Unable to write to console");
        }
        StringBuilder sb = new StringBuilder();
        message(prompt+":");
        message
            ("Type in your text. End with a line containing a single .");
        message("");

        boolean first = true;
        String sep = System.getProperty("line.separator", "\n");
        while (true) {
            String line = cons.readLine();
            if (line == null) { return null; }
            if (".".equals(line)) {
                return sb.toString();
            }
            if (first) { first = false; }
            else { sb.append(sep); }
            sb.append(line);
        }
    }

    public final static String readString(String prompt, String dflt)
    {
        Console cons;
        if ((cons = System.console()) == null) {
            throw new IllegalStateException("Unable to write to console");
        }
        String ret = null;
        while (true) {
            if (dflt != null) {
                ret = cons.readLine("%s [%s]: ", prompt, dflt);
            }
            else {
                ret = cons.readLine("%s: ", prompt);
            }

            if (ret == null) { return null; } // eof

            ret = ret.trim();
            if (ret.length() > 0) {
                return ret;
            }
            else {
                // hit return for default
                if (dflt != null) { return dflt; }
            }
        }
    }
}
