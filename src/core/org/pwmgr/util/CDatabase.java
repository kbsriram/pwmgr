package org.pwmgr.util;

/**
 * The password database is serialized (and also represented)
 * as a simple JSON object.
 *
 */

import org.jsonjava.JSONObject;
import org.jsonjava.JSONTokener;
import org.jsonjava.JSONException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPException;

import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.io.IOException;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;

public class CDatabase
{
    public final static CDatabase load(CConfig config, char[] pw)
        throws IOException, JSONException
    {
        PGPSecretKeyRing skr = loadVerifiedKeyRing(config, pw);

        // Decrypt password db with private key. This is
        // asymmetrically encrypted and signed with the same
        // private key.

        File dbroot =
            new File(config.getArgOption(CConfig.ArgOption.PUBLIC));

        BufferedInputStream bin =
            new BufferedInputStream
            (new FileInputStream
             (new File(dbroot, CConfig.PWDB)));
        byte[] jsonbytes =
            CPGPUtils.asymmetricDecryptAndVerify
            (bin, CPGPUtils.getEncryptionSecretKey(skr), pw,
             CPGPUtils.getSigningSecretKey(skr).getPublicKey());
        bin.close();

        // 6. Render as json and return.
        return new CDatabase
            (new JSONObject
             (new JSONTokener
              (new ByteArrayInputStream(jsonbytes))));
    }

    public static CDatabase newDatabase()
        throws JSONException
    {
        JSONObject js = new JSONObject();
        js.put(VERSION, 1);
        js.put(ENTRIES, new JSONObject());
        return new CDatabase(js);
    }

    private final static PGPSecretKeyRing
        loadVerifiedKeyRing(CConfig config, char[] pw)
        throws IOException
    {
        // 1. Load public key
        File dbroot =
            new File(config.getArgOption(CConfig.ArgOption.PUBLIC));
        
        BufferedInputStream  bin =
            new BufferedInputStream
            (new FileInputStream
             (new File(dbroot, CConfig.PUBKEY)));
        PGPPublicKeyRing pkr = CPGPUtils.readPublicKeyRing(bin);
        bin.close();

        // 2. Decrypt symmetric encrypted data for private key. It's
        // encrypted with the master password, and signed with the
        // public key from step 1.
        bin =
            new BufferedInputStream
            (new FileInputStream
             (config.getArgOption(CConfig.ArgOption.PRIVATE)));
        byte[] seckeybytes = 
            CPGPUtils.symmetricDecryptAndVerify
            (bin, pw, CPGPUtils.getSigningPublicKey(pkr));
        bin.close();

        // 3. Load private key.
        ByteArrayInputStream bain = new ByteArrayInputStream(seckeybytes);
        PGPSecretKeyRing skr = CPGPUtils.readSecretKeyRing(bain, pw);
        bain.close();

        // 4. Verify this private key is the same as the public key
        // from step 1.
        if (!CPGPUtils.haveSameKeys(pkr, skr)) {
            throw new IOException("Private keys don't match public keys.");
        }
        return skr;
    }

    public Entry getById(String id)
        throws JSONException
    {
        JSONObject entries = m_json.getJSONObject(ENTRIES);
        String key = id.toLowerCase();
        JSONObject ejs = entries.optJSONObject(key);
        if (ejs != null) {
            return new Entry(ejs);
        }
        return null;
    }
        
    public CDatabase removeById(String id)
        throws JSONException
    {
        JSONObject entries = m_json.getJSONObject(ENTRIES);
        String key = id.toLowerCase();
        entries.remove(id.toLowerCase());
        return this;
    }

    public List<Entry> looksLike(String id)
        throws JSONException
    {
        JSONObject entries = m_json.getJSONObject(ENTRIES);
        String key = id.toLowerCase();
        List<Entry> ret = new ArrayList<Entry>();
        for (Object o: entries.keySet()) {
            String k = o.toString();
            if (k.indexOf(key) >= 0) {
                ret.add(new Entry(entries.getJSONObject(k)));
            }
        }
        return ret;
    }

    public void save(CConfig config, char[] pw)
        throws IOException, JSONException
    {
        PGPSecretKeyRing skr = loadVerifiedKeyRing(config, pw);
        save(config, skr, pw);
    }
    public void save(CConfig config, PGPSecretKeyRing skr, char[] pw)
        throws IOException, JSONException
    {
        // Carefully write new file, and backup the existing file
        // if successful.
        File dbroot = new File
            (config.getArgOption(CConfig.ArgOption.PUBLIC));

        File nfile = new File(dbroot, "new_"+CConfig.PWDB);
        File curfile = new File(dbroot, CConfig.PWDB);
        File ofile = new File(dbroot, "prev_"+CConfig.PWDB);

        boolean ok = false;
        BufferedOutputStream out = null;
        try {
            // 1. Serialize json to byte array.
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            Writer w = new OutputStreamWriter(bout);
            m_json.write(w);
            w.close();
            byte[] jsbytes = bout.toByteArray();

            // 2. Encrypt, sign and write to new file.
            out = new BufferedOutputStream(new FileOutputStream(nfile));
            CPGPUtils.asymmetricEncryptAndSign
                (jsbytes, out,
                 CPGPUtils.getEncryptionSecretKey(skr).getPublicKey(),
                 CPGPUtils.getSigningSecretKey(skr), pw,
                 "_CONSOLE", new Date());
            out.close();
            out = null;

            // 3. Delete any prev_file, and rotate files.
            if (ofile.exists()) {
                if (!ofile.delete()) {
                    throw new IOException("Unable to delete "+ofile);
                }
            }
            if (curfile.exists()) {
                if (!curfile.renameTo(ofile)) {
                    throw new IOException("Unable to move "+curfile+
                                          " to "+ofile);
                }
            }
            if (!nfile.renameTo(curfile)) {
                throw new IOException("Unable to rename "+nfile+
                                      " to "+curfile);
            }
            ok = true;
        }
        finally {
            if (!ok) {
                if (out != null) {
                    try { out.close(); } catch (Throwable ign) {}
                }
                nfile.delete();
            }
        }
    }

    public void addEntry
        (String id, String name, String notes, char[] pw)
        throws JSONException
    {
        String key = id.toLowerCase();
        JSONObject entries = m_json.getJSONObject(ENTRIES);
        if (entries.has(key)) {
            throw new JSONException("Duplicate entry: "+id);
        }
        JSONObject entry = new JSONObject();
        entry.put(ENTRY_ID, id);
        entry.put(ENTRY_USERNAME, name);
        entry.put(ENTRY_NOTES, notes);
        entry.put(ENTRY_PASSWORD, new String(pw));
        entry.put(ENTRY_CREATED, System.currentTimeMillis());
        entry.put(ENTRY_MODIFIED, System.currentTimeMillis());
        entries.put(key, entry);
    }

    private CDatabase(JSONObject json)
    { m_json = json; }
    private final JSONObject m_json;
    private final static String VERSION = "version";
    private final static String ENTRIES = "entries";
    private final static String ENTRY_ID = "id";
    private final static String ENTRY_NOTES = "notes";
    private final static String ENTRY_PASSWORD = "passwd";
    private final static String ENTRY_USERNAME = "name";
    private final static String ENTRY_CREATED = "created";
    private final static String ENTRY_MODIFIED = "modified";

    public final static class Entry
    {
        private Entry(JSONObject ejs)
        { m_ejson = ejs; }
        public String getId()
            throws JSONException
        { return m_ejson.getString(ENTRY_ID); }
        public String getUserName()
            throws JSONException
        { return m_ejson.getString(ENTRY_USERNAME); }
        public Entry setUserName(String s)
            throws JSONException
        { m_ejson.put(ENTRY_USERNAME, s); return this;}
        public String getNotes()
            throws JSONException
        { return m_ejson.getString(ENTRY_NOTES); }
        public Entry setNotes(String s)
            throws JSONException
        { m_ejson.put(ENTRY_NOTES, s); return this; }
        public String getPassword()
            throws JSONException
        { return m_ejson.getString(ENTRY_PASSWORD); }
        public Entry setPassword(String s)
            throws JSONException
        { m_ejson.put(ENTRY_PASSWORD, s); return this;}
        public long getCreated()
            throws JSONException
        { return m_ejson.getLong(ENTRY_CREATED); }
        public long getModified()
            throws JSONException
        { return m_ejson.getLong(ENTRY_MODIFIED); }
        private final JSONObject m_ejson;
    }
}
