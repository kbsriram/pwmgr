package org.pwmgr.util;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;

import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.BufferedInputStream;
import java.io.FileInputStream;

import java.util.Date;
import java.util.Random;

public class CPGPUtilTest
{
    @Test public void testGenerate()
        throws Exception
    {
        char[] pass = "1234".toCharArray();

        PGPKeyRingGenerator krgen =
            CPGPUtils.generateKeyRingGenerator("test", pass, 0x60);
        PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
        PGPSecretKeyRing skr = krgen.generateSecretKeyRing();

        BufferedOutputStream bout =
            new BufferedOutputStream(new FileOutputStream("/tmp/test.pkr"));
        pkr.encode(bout);
        bout.close();
        bout =
            new BufferedOutputStream(new FileOutputStream("/tmp/test.skr"));
        skr.encode(bout);
        bout.close();

        bout =
            new BufferedOutputStream(new FileOutputStream("/tmp/test.gpg"));
        byte[] data = "Hello, world!".getBytes("utf-8");
        char[] encpass = "abc".toCharArray();

        CPGPUtils.realSymmetricEncryptAndSign
            (data, bout, encpass,
             CPGPUtils.getSigningSecretKey(skr), pass,
             "_CONSOLE", new Date(), 0x60);
        bout.close();

        bout =
            new BufferedOutputStream
            (new FileOutputStream("/tmp/test-a.gpg"));

        CPGPUtils.asymmetricEncryptAndSign
            (data, bout, CPGPUtils.getEncryptionPublicKey(pkr),
             CPGPUtils.getSigningSecretKey(skr), pass,
             "_CONSOLE", new Date());
        bout.close();

        FileInputStream fin = new FileInputStream("/tmp/test.pkr");
        byte[] pkbytes = new byte[fin.available()];
        fin.read(pkbytes);
        fin.close();

        for (int i=0; i<pkbytes.length; i++) {
            byte save = pkbytes[i];
            fuzz(pkbytes, i);
            checkPK(pkbytes, i);
            pkbytes[i] = save;
        }

        fin = new FileInputStream("/tmp/test.skr");
        byte[] skbytes = new byte[fin.available()];
        fin.read(skbytes);
        fin.close();

        for (int i=0; i<skbytes.length; i++) {
            byte save = skbytes[i];
            fuzz(skbytes, i);
            checkSK(skbytes, i, encpass);
            skbytes[i] = save;
        }


        fin = new FileInputStream("/tmp/test.gpg");
        byte[] result = CPGPUtils.symmetricDecryptAndVerify
            (fin, encpass, CPGPUtils.getSigningPublicKey(pkr));
        assertEquals(result.length, data.length);
        for (int i=0; i<result.length; i++) {
            assertEquals(result[i], data[i]);
        }
        fin.close();

        fin = new FileInputStream("/tmp/test.gpg");
        byte[] edata = new byte[fin.available()];
        fin.read(edata);
        fin.close();
        for (int i=0; i<edata.length; i++) {
            byte save = edata[i];
            fuzz(edata, i);
            checkDecrypt(edata, encpass, i, pkr);
            edata[i] = save;
        }

        fin = new FileInputStream("/tmp/test-a.gpg");
        result = CPGPUtils.asymmetricDecryptAndVerify
            (fin, CPGPUtils.getEncryptionSecretKey(skr), pass,
             CPGPUtils.getSigningPublicKey(pkr));
        assertEquals(result.length, data.length);
        for (int i=0; i<result.length; i++) {
            assertEquals(result[i], data[i]);
        }
        fin.close();

        fin = new FileInputStream("/tmp/test-a.gpg");
        edata = new byte[fin.available()];
        fin.read(edata);
        fin.close();
        for (int i=0; i<edata.length; i++) {
            byte save = edata[i];
            fuzz(edata, i);
            checkDecryptA(edata, skr, pass, i, pkr);
            edata[i] = save;
        }
    }

    private void checkDecrypt
        (byte[] data, char[] pass, int id, PGPPublicKeyRing pkr)
        throws IOException
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        boolean ok = false;
        try {
            byte[] contents = CPGPUtils.symmetricDecryptAndVerify
                (bin, pass, CPGPUtils.getSigningPublicKey(pkr));
        }
        catch (IOException ioe) {
            // This is desired.
            // System.err.println("Caught sd-issue: "+ioe);
            ok = true;
        }

        if (!ok) {
            save(data, "/tmp/sbad/fuzz-"+id+".dat");
        }
    }

    private void checkDecryptA
        (byte[] data, PGPSecretKeyRing skr, char[] pass,
         int id, PGPPublicKeyRing pkr)
        throws IOException
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        boolean ok = false;
        try {
            byte[] contents = CPGPUtils.asymmetricDecryptAndVerify
                (bin, CPGPUtils.getEncryptionSecretKey(skr), pass,
                 CPGPUtils.getSigningPublicKey(pkr));
        }
        catch (IOException ioe) {
            // This is desired.
            System.err.println("Found asym-issue: "+ioe);
            ok = true;
        }

        if (!ok) {
            save(data, "/tmp/abad/fuzz-"+id+".dat");
        }
    }

    private void checkPK(byte[] data, int id)
        throws IOException
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        boolean ok = false;
        try {
            PGPPublicKeyRing check_pkr = CPGPUtils.readPublicKeyRing(bin);
        }
        catch (IOException ioe) {
            // This is desired.
            ok = true;
        }

        if (!ok) {
            save(data, "/tmp/bad/fuzz-"+id+".pkr");
        }
    }

    private void checkSK(byte[] data, int id, char[] pw)
        throws IOException
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(data);
        boolean ok = false;
        try {
            PGPSecretKeyRing check_skr =
                CPGPUtils.readSecretKeyRing(bin, pw);
        }
        catch (IOException ioe) {
            // This is desired.
            // System.err.println("Caught sk-fuzz: "+ioe);
            ok = true;
        }

        if (!ok) {
            save(data, "/tmp/badsk/fuzz-"+id+".skr");
        }
    }

    private final static void fuzz(byte[] data, int location)
    {
        byte n = data[location];
        do { data[location] = (byte) s_random.nextInt(); }
        while (n == data[location]);
    }

    private final static void save(byte[] data, String path)
        throws IOException
    {
        File f = new File(path);
        File p = f.getParentFile();
        if ((p != null) && (!p.isDirectory())) {
            p.mkdirs();
        }
        FileOutputStream fout = new FileOutputStream(f);
        fout.write(data);
        fout.close();
    }

    private final static Random s_random = new Random();
}
