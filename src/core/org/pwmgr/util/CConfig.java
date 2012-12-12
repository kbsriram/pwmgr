package org.pwmgr.util;

import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;

import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;

public class CConfig
{
    public static CConfig getConfig(String[] args)
        throws IOException
    {
        Properties p = new Properties();
        File dflt = new File(System.getProperty("user.home"),
                               CONFIG_FILE);
        if (dflt.canRead()) {
            BufferedReader br = new BufferedReader(new FileReader(dflt));
            try { p.load(br); }
            finally { br.close(); }
        }
        CConfig ret = init(p);

        // Override with any options.
        List<String> cargs = new ArrayList<String>();
        int i = 0;
        Command c = null;

        while (i < args.length) {
            String cur = args[i];

            // Not an option
            if (!cur.startsWith("-")) {
                if (c == null) {
                    c = asCommand(cur);
                    if (c == null) {
                        return bail("Unknown command '"+cur+"'");
                    }
                    ret.setCommand(c);
                }
                else {
                    cargs.add(cur);
                }
                i++;
                continue;
            }

            // Handle options
            String opt_name = cur.substring(1);

            // With an argument
            ArgOption ao = asArgOption(opt_name);
            if (ao != null) {
                i++;
                if (i >= args.length) {
                    return bail(cur+" needs an argument");
                }
                String aoarg = args[i++];
                if (aoarg.startsWith("-")) {
                    return bail(cur+" needs an argument");
                }
                ret.setArgOption(ao, aoarg);
                continue;
            }

            // Boolean option
            BooleanOption bo = asBooleanOption(opt_name);
            if (bo == null) {
                return bail("Unknown option "+cur);
            }
            ret.setBooleanOption(bo);
            i++;
        }

        if (ret.hasBooleanOption(BooleanOption.HELP)) {
            usage();
            return null;
        }

        if (c == null) {
            return bail("No command specified");
        }
        ret.setArgs(cargs);
        return ret;
    }

    public boolean passBasicChecks()
    {
        if (!checkPubDir(getArgOption(ArgOption.PUBLIC))) {
            return false;
        }
        if (!checkPrivKey(getArgOption(ArgOption.PRIVATE))) {
            return false;
        }
        return true;
    }

    private final static boolean checkPrivKey(String d)
    {
        if (d == null) {
            bail("Missing -private option");
            return false;
        }
        File p = new File(d);

        if (!p.canRead()) {
            bail("Cannot read private key: "+p, false);
            return false;
        }
        return true;
    }

    private final static boolean checkPubDir(String d)
    {
        if (d == null) {
            bail("Missing -public option");
            return false;
        }
        File root = new File(d);

        if (!root.isDirectory()) {
            bail(root+" is not a directory", false);
            return false;
        }
        File pubkey = new File(root, PUBKEY);
        if (!pubkey.canRead()) {
            bail("Cannot read public key: "+pubkey, false);
            return false;
        }
        File pwdb = new File(root, PWDB);
        if (!pwdb.canRead()) {
            bail("Cannot read password db: "+pwdb, false);
            return false;
        }
        return true;
    }

    private final static ArgOption asArgOption(String s)
    {
        for (ArgOption o: ArgOption.values()) {
            if (o.m_v.equals(s)) {
                return o;
            }
        }
        return null;
    }
    private final static BooleanOption asBooleanOption(String s)
    {
        for (BooleanOption o: BooleanOption.values()) {
            if (o.m_v.equals(s)) {
                return o;
            }
        }
        return null;
    }
    private final static Command asCommand(String s)
    {
        for (Command o: Command.values()) {
            if (o.m_v.equals(s)) {
                return o;
            }
        }
        return null;
    }
    private final static void usage()
    {
        System.out.println("Options:");
        for (BooleanOption bo: BooleanOption.values()) {
            format("-"+bo.m_v, bo.m_d);
        }
        for (ArgOption ao: ArgOption.values()) {
            format("-"+ao.m_v+" <"+ao.m_a+">", ao.m_d);
        }

        System.out.println();
        System.out.println("Commands:");
        for (Command c: Command.values()) {
            format(c.m_v, c.m_d);
        }
    }
    private final static void format(String a, String b)
    {
        int spaces = 20-a.length();
        if (spaces < 3) { spaces = 3; }
        System.out.print("  ");
        System.out.print(a);
        for (int i=0; i<spaces; i++) {
            System.out.print(" ");
        }
        System.out.println(b);
    }

    private final static CConfig init(Properties p)
    {
        CConfig ret = new CConfig();
        for (Object o: p.keySet()) {
            String k = o.toString();
            ArgOption ao = asArgOption(k);
            if (ao != null) {
                ret.setArgOption(ao, p.getProperty(k));
                continue;
            }
            BooleanOption bo = asBooleanOption(k);
            if (bo != null) {
                ret.setBooleanOption(bo);
                continue;
            }
            throw new IllegalArgumentException
                ("Unknown property in config: "+k);
        }
        return ret;            
    }

    public final static CConfig bail(String msg)
    { return bail(msg, true); }

    public final static CConfig bail(String msg, boolean showUsage)
    {
        CConsole.error(msg);
        if (showUsage) {
            System.out.println();
            usage();
        }
        return null;
    }

    private CConfig()  {}

    public Command getCommand()
    { return m_command; }
    public boolean hasBooleanOption(BooleanOption bo)
    { return m_bo.contains(bo); }
    public String getArgOption(ArgOption ao)
    { return m_ao.get(ao); }
    public CConfig setBooleanOption(BooleanOption bo)
    { m_bo.add(bo); return this; }
    public CConfig setArgOption(ArgOption ao, String v)
    { m_ao.put(ao, v); return this; }
    public List<String> getArgs()
    { return m_args; }
    private void setCommand(Command c)
    { m_command = c; }
    private void setArgs(List<String> args)
    { m_args = args; }

    private Command m_command;
    private final HashSet<BooleanOption> m_bo = new HashSet<BooleanOption>();
    private final HashMap<ArgOption,String> m_ao =
        new HashMap<ArgOption,String>();
    private List<String> m_args;

    public enum Command
    {
        SHOW("show", "<entry> -- Show name and copy password for <entry>."),
        NOTES("notes", "<entry> -- Show name and notes for <entry>."),
        LIST("list", "[entry] -- List all names, optionally matching [entry]."),


        ADD("add", "Add a new password entry."),
        EDIT("edit", "<entry> -- Modify an existing password entry."),
        REMOVE("remove", "<entry> -- Remove <entry> from database."),


        INIT("init", "Initialize a new password database."),
        REMASTER("remaster", "Generate a new database from current, with new keys.");
        Command(String v, String d) {m_v = v; m_d = d;}
        public String getName() { return m_v; }
        private String m_v; private String m_d; 
    };
    public enum BooleanOption
    {
        HELP("help", "Dump this message");
        BooleanOption(String v, String d) {m_v = v; m_d = d;}
        private String m_v; private String m_d; 
    };
    public enum ArgOption
    {
        PUBLIC("public", "dir",
               "Specify the directory containing the password database"),
        PRIVATE("private", "file",
               "Specify the path to the encrypted private key");
        ArgOption(String v, String a, String d)
        {m_v = v; m_a = a; m_d = d;}
        public String getName() { return m_v; }
        private String m_v; private String m_a; private String m_d;
    };

    private final static String CONFIG_FILE = ".pwmgr";
    public final static String PUBKEY = "public.pkr";
    public final static String PWDB = "db.pgp";
}
