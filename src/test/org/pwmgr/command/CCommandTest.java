package org.pwmgr.command;

import org.pwmgr.util.CConfig;
import org.pwmgr.util.CDatabase;

import java.io.File;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class CCommandTest
{
    private static File s_root;
    private static boolean s_delete = false;
    @BeforeClass public static void createDir()
        throws Exception
    {
        File f = File.createTempFile("pwmgr-command-test", null);
        f.delete();
        f.mkdirs();
        s_root = f;
        System.out.println("Generate to "+s_root);
    }

    @AfterClass public static void deleteDir()
        throws Exception
    {
        if (s_delete) {
            System.out.println("Delete "+s_root);
            delRoot(s_root);
        }
    }

    private final static void delRoot(File root)
        throws Exception
    {
        if (root.isDirectory()) {
            File[] children = root.listFiles();
            for (int i=0; i<children.length; i++) {
                delRoot(children[i]);
            }
        }
        root.delete();
    }

    @Test public void testGenerate()
        throws Exception
    {
        File pubroot = new File(s_root, "db");
        File priv = new File(s_root, "private.pgp");

        String pw = "abc";

        // Test init.
        CConfig config = CConfig.getConfig
            (new String[] {
                "-"+CConfig.ArgOption.PUBLIC.getName(), pubroot.toString(),
                "-"+CConfig.ArgOption.PRIVATE.getName(), priv.toString(),
                CConfig.Command.INIT.getName()
            });
        CDatabase db = CDatabase.newDatabase();

        CInit.init(db, config, pw.toCharArray());

        // Test adding something.
        config = CConfig.getConfig
            (new String[] {
                "-"+CConfig.ArgOption.PUBLIC.getName(), pubroot.toString(),
                "-"+CConfig.ArgOption.PRIVATE.getName(), priv.toString(),
                CConfig.Command.ADD.getName()
            });
        db = CDatabase.load(config, pw.toCharArray());
        CAdd.add(config, db,
                 "firstid", "firstname", "firstnote",
                 "first".toCharArray(), pw.toCharArray());

        // We should be able to list and search for this key.
        db = CDatabase.load(config, pw.toCharArray());
        assertNotNull(db.getById("firstid"));
        assertEquals(1, db.looksLike("i").size());
        assertEquals(0, db.looksLike("o").size());

        // Finally, should be able to delete it.
        db.removeById("firstid").save(config, pw.toCharArray());

        // Check it really got removed.
        db = CDatabase.load(config, pw.toCharArray());
        assertNull(db.getById("firstid"));
        assertEquals(0, db.looksLike("").size());

        s_delete = true;
    }
}
