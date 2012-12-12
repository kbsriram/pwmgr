package org.pwmgr.util;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.List;
import java.util.Iterator;

public class CPGPUtils
{
    // Symmetric decryption, and check signature with provided
    // key.
    public final static byte[] symmetricDecryptAndVerify
        (InputStream in, char encpass[], PGPPublicKey signkey)
        throws IOException
    {
        try {return realSymmetricDecryptAndVerify(in, encpass, signkey);}
        catch (IOException ioe) {
            throw ioe;
        }
        catch (Throwable th) {
            throw new IOException(th);
        }
    }

    // Asymmetric decryption, and check signature with provided
    // key.
    public final static byte[] asymmetricDecryptAndVerify
        (InputStream in, PGPSecretKey sk, char pw[],
         PGPPublicKey pk)
        throws IOException
    {
        try {return realAsymmetricDecryptAndVerify(in, sk, pw, pk);}
        catch (IOException ioe) {
            throw ioe;
        }
        catch (Throwable th) {
            throw new IOException(th);
        }
    }

    // Symmetric encryption, and signed with the provided signing key
    public final static void symmetricEncryptAndSign
        (byte[] inbytes, OutputStream out, char encpass[],
         PGPSecretKey sk, char keypass[],
         String name, Date modtime)
        throws IOException
    {
        try {
            realSymmetricEncryptAndSign
                (inbytes, out, encpass, sk, keypass, name, modtime,
                 0xff);
        }
        catch (PGPException pge) {
            throw new IOException(pge);
        }
        catch (SignatureException sge) {
            throw new IOException(sge);
        }
    }

    // Asymmetric encryption, and signed with the provided signing key
    public final static void asymmetricEncryptAndSign
        (byte[] inbytes, OutputStream out, PGPPublicKey enckey,
         PGPSecretKey signkey, char keypass[],
         String name, Date modtime)
        throws IOException
    {
        try {
            realAsymmetricEncryptAndSign
                (inbytes, out, enckey, signkey, keypass, name, modtime);
        }
        catch (PGPException pge) {
            throw new IOException(pge);
        }
        catch (SignatureException sge) {
            throw new IOException(sge);
        }
    }


    final static void realAsymmetricEncryptAndSign
        (byte[] inbytes, OutputStream out, PGPPublicKey encpubkey,
         PGPSecretKey signkey, char keypass[],
         String name, Date modtime)
        throws IOException, PGPException, SignatureException
    {
        // the desired packet structure is:
        // encrypt+mdc:
        //    compress:
        //       one-pass-signature
        //       data
        //       signature(data)

        // NB: actual integrity comes from the signature, though the mdc
        // adds additional protection.

        PGPPrivateKey signprivkey = extractPrivateKey(signkey, keypass);

        encryptUsing(inbytes, out, name, modtime,
                     new BcPublicKeyKeyEncryptionMethodGenerator
                     (encpubkey), signkey.getPublicKey().getAlgorithm(),
                     signprivkey);
    }

    private final static void encryptUsing
        (byte[] inbytes, OutputStream out, String name, Date modtime,
         PGPKeyEncryptionMethodGenerator mgen,
         int algorithm, PGPPrivateKey signkey)
        throws IOException, PGPException, SignatureException
    {
        PGPEncryptedDataGenerator encGen =
            new PGPEncryptedDataGenerator
            (new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
             .setWithIntegrityPacket(true));

        encGen.addMethod(mgen);

        // Write to output via the encrypter
        OutputStream encOut = encGen.open(out, new byte[1<<16]);

        // Write to encrypter via a compressor
        PGPCompressedDataGenerator comGen =
            new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream comOut = comGen.open(encOut);

        // Pipe bytes to the compressor via a signer
        pipeSignedBytes(inbytes, comOut, algorithm,
                        signkey, name, modtime);

        // close generators in reverse, which flushes out the data
        // at each stage.
        comGen.close();
        encGen.close();
    }

    final static void realSymmetricEncryptAndSign
        (byte[] inbytes, OutputStream out, char encpass[],
         PGPSecretKey psk, char keypass[],
         String name, Date modtime, int s2kcount)
        throws IOException, PGPException, SignatureException
    {
        // the desired packet structure is:
        // encrypt+mdc:
        //    compress:
        //       one-pass-signature
        //       data
        //       signature(data)

        // NB: actual integrity comes from the signature, though the mdc
        // adds additional protection.

        PGPPublicKey pubkey = psk.getPublicKey();
        PGPPrivateKey privkey = extractPrivateKey(psk, keypass);

        encryptUsing
            (inbytes, out, name, modtime,
             (new BcPBEKeyEncryptionMethodGenerator
              (encpass, new BcPGPDigestCalculatorProvider()
               .get(HashAlgorithmTags.SHA256), s2kcount)),
             pubkey.getAlgorithm(), privkey);
    }

    public final static PGPKeyRingGenerator generateKeyRingGenerator
        (String id, char[] pass)
    { return generateKeyRingGenerator(id, pass, 0xff); }

    public final static PGPKeyRingGenerator generateKeyRingGenerator
        (String id, char[] pass, int s2kcount)
    {
        try {
            RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();
            kpg.init
                (new RSAKeyGenerationParameters
                 (BigInteger.valueOf(0x10001),
                  new SecureRandom(), 4096, 12));

            // Create a signing master key with an encryption subkey. 
            PGPKeyPair rsakp_sign =
                new BcPGPKeyPair
                (PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
            PGPKeyPair rsakp_enc =
                new BcPGPKeyPair
                (PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

            PGPSignatureSubpacketGenerator signhashgen =
                new PGPSignatureSubpacketGenerator();
            signhashgen.setPreferredSymmetricAlgorithms
                (false, new int[] { SymmetricKeyAlgorithmTags.AES_256 });
            signhashgen.setPreferredHashAlgorithms
                (false, new int[] { HashAlgorithmTags.SHA256 });
            signhashgen.setKeyFlags
                (false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);
            signhashgen.setFeature
                (false, Features.FEATURE_MODIFICATION_DETECTION);

            PGPSignatureSubpacketGenerator enchashgen =
                new PGPSignatureSubpacketGenerator();
            enchashgen.setKeyFlags
                (false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

            PGPDigestCalculator sha1Calc =
                new BcPGPDigestCalculatorProvider()
                .get(HashAlgorithmTags.SHA1);
            PGPDigestCalculator sha256Calc =
                new BcPGPDigestCalculatorProvider()
                .get(HashAlgorithmTags.SHA256);

            PBESecretKeyEncryptor pske =
                (new BcPBESecretKeyEncryptorBuilder
                 (PGPEncryptedData.AES_256, sha256Calc, s2kcount))
                .build(pass);

            // Create the keyring.
            PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator
                (PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                 id, sha1Calc, signhashgen.generate(), null,
                 new BcPGPContentSignerBuilder
                 (rsakp_sign.getPublicKey().getAlgorithm(),
                  HashAlgorithmTags.SHA1),
                 pske);

            keyRingGen.addSubKey
                (rsakp_enc, enchashgen.generate(), null);
            return keyRingGen;
        }
        catch (Exception pge) {
            throw new RuntimeException(pge);
        }
    }

    @SuppressWarnings("unchecked")
    public final static boolean haveSameKeys
        (PGPPublicKeyRing pkr, PGPSecretKeyRing skr)
    {
        Iterator<PGPSecretKey> skit = skr.getSecretKeys();
        Iterator<PGPPublicKey> pkit = pkr.getPublicKeys();
        while (skit.hasNext()) {
            if (!pkit.hasNext()) { return false; }
            PGPSecretKey sk = skit.next();
            PGPPublicKey pk = pkit.next();

            // compare with fingerprints.
            if (!sameFingerprint(pk, sk.getPublicKey())) { return false; }
        }
        if (pkit.hasNext()) { return false; }
        return true;
    }

    public final static boolean sameFingerprint
        (PGPPublicKey a, PGPPublicKey b)
    {
        byte[] afp = a.getFingerprint();
        byte[] bfp = b.getFingerprint();
        if (afp.length != bfp.length) { return false; }
        for (int i=0; i<afp.length; i++) {
            if (afp[i] != bfp[i]) { return false; }
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKey getSigningSecretKey
        (PGPSecretKeyRing pskr)
    {
        Iterator<PGPSecretKey> it= pskr.getSecretKeys();
        while (it.hasNext()) {
            PGPSecretKey candidate = it.next();
            if (isSigningKey(candidate.getPublicKey())) {
                return candidate;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public final static PGPSecretKey getEncryptionSecretKey
        (PGPSecretKeyRing skr)
    {
        Iterator<PGPSecretKey> it= skr.getSecretKeys();
        while (it.hasNext()) {
            PGPSecretKey candidate = it.next();
            if (isEncryptionKey(candidate.getPublicKey())) {
                return candidate;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public final static PGPPublicKey getEncryptionPublicKey
        (PGPPublicKeyRing pkr)
    {
        Iterator<PGPPublicKey> it= pkr.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey candidate = it.next();
            if (isEncryptionKey(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public final static PGPPublicKey getSigningPublicKey
        (PGPPublicKeyRing pkr)
    {
        Iterator<PGPPublicKey> it= pkr.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey candidate = it.next();
            if (isSigningKey(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private final static boolean isSigningKey(PGPPublicKey pk)
    { return pk.getAlgorithm() == PGPPublicKey.RSA_SIGN; }
    private final static boolean isEncryptionKey(PGPPublicKey pk)
    { return pk.getAlgorithm() == PGPPublicKey.RSA_ENCRYPT; }

    public final static PGPPublicKeyRing readPublicKeyRing
        (InputStream inp)
        throws IOException
    {
        try { return realReadPublicKeyRing(inp); }
        catch (IOException ioe) {
            throw ioe;
        }
        catch (Throwable th) {
            // Bad input may cause RuntimeExceptions.
            throw new IOException(th);
        }
    }

    public final static PGPSecretKeyRing readSecretKeyRing
        (InputStream inp, char pw[])
        throws IOException
    {
        try { return realReadSecretKeyRing(inp, pw); }
        catch (IOException ioe) {
            throw ioe;
        }
        catch (Throwable th) {
            // Bad input may cause RuntimeExceptions.
            throw new IOException(th);
        }
    }


    @SuppressWarnings("unchecked")
    private final static byte[] realAsymmetricDecryptAndVerify
        (InputStream inp, PGPSecretKey encsk, char encpass[],
         PGPPublicKey signkey)
        throws IOException, PGPException, SignatureException
    {
        PGPPrivateKey enckey = extractPrivateKey(encsk, encpass);

        inp = PGPUtil.getDecoderStream(inp);

        PGPObjectFactory        pgpF = new PGPObjectFactory(inp);
        Object                  o = pgpF.nextObject();
        if (!(o instanceof PGPEncryptedDataList)) {
            throw new IOException
                ("Expected encrypted session keys, got : "+o.getClass());
        }
        PGPEncryptedDataList edl = (PGPEncryptedDataList) o;
        if (edl.size() != 1) {
            throw new IOException
                ("Expected one encrypted packet, got : "+edl.size());
        }
        o = edl.get(0);
        if (!(o instanceof PGPPublicKeyEncryptedData)) {
            throw new IOException
                ("Expected pubkey encrypted data, got : "+o.getClass());
        }
        PGPPublicKeyEncryptedData pkdata = (PGPPublicKeyEncryptedData) o;

        // Check if keyids match; unless we have a wildcard
        // packet.
        if ((pkdata.getKeyID() != 0l) &&
            (pkdata.getKeyID() != enckey.getKeyID())) {
            throw new IOException
                ("Data is not encrypted with the available key.");
        }

        InputStream decoded = pkdata.getDataStream
            (new BcPublicKeyDataDecryptorFactory(enckey));

        return extractAndVerify(pkdata, decoded, signkey);
    }

    private final static byte[] extractAndVerify
        (PGPEncryptedData edata, InputStream decoded, PGPPublicKey signkey)
        throws PGPException, IOException, SignatureException
    {
        if (!edata.isIntegrityProtected()) {
            throw new IOException
                ("Contents not integrity protected, rejecting");
        }
        PGPObjectFactory decodedF = new PGPObjectFactory(decoded);
        // Expect to find a compressed packet.
        Object o = decodedF.nextObject();
        if (!(o instanceof PGPCompressedData)) {
            throw new IOException
                ("Did not find compressed data: "+o.getClass());
        }

        // Swap in factory.
        decodedF = new PGPObjectFactory
            (((PGPCompressedData)o).getDataStream());

        // Need a signature header.
        PGPOnePassSignature ops = expectOPS(decodedF);

        // Verify that keyid specified in the signature matches the
        // signing key from the keyring.
        if (ops.getKeyID() != signkey.getKeyID()) {
            throw new IOException
                ("Data not signed with the correct key.");
        }

        // Next, a literal object.
        o = decodedF.nextObject();
        if (!(o instanceof PGPLiteralData)) {
            throw new IOException
                ("Expected literal data, got: "+o.getClass());
        }
        PGPLiteralData ld = (PGPLiteralData) o;

        // Start copying the data to an output buffer, while
        // also updating the signature hash.
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ops.init(s_provider, signkey);
        InputStream ldin = ld.getInputStream();
        byte[] buf = new byte[8192];
        int nread;
        while ((nread = ldin.read(buf)) > 0) {
            bout.write(buf, 0, nread);
            ops.update(buf, 0, nread);
        }
        bout.close();

        // Expect a trailing signature, and check it.
        if (!ops.verify(expectSignature(decodedF))) {
            throw new IOException("Bad signature, rejecting data.");
        }

        // Expect no more data.
        if (decodedF.nextObject() != null) {
            throw new IOException("Unexpected trailing data, reject.");
        }
        // Verify MDC as well.
        if (!edata.verify()) {
            throw new IOException("Bad integrity check, rejecting data.");
        }

        return bout.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private final static byte[] realSymmetricDecryptAndVerify
        (InputStream inp, char encpass[], PGPPublicKey signkey)
        throws IOException, PGPException, SignatureException
    {
        inp = PGPUtil.getDecoderStream(inp);

        PGPObjectFactory        pgpF = new PGPObjectFactory(inp);
        Object                  o = pgpF.nextObject();
        if (!(o instanceof PGPEncryptedDataList)) {
            throw new IOException
                ("Expected encrypted session keys, got : "+o.getClass());
        }
        PGPEncryptedDataList edl = (PGPEncryptedDataList) o;
        if (edl.size() != 1) {
            throw new IOException
                ("Expected one encrypted packet, got : "+edl.size());
        }
        o = edl.get(0);
        if (!(o instanceof PGPPBEEncryptedData)) {
            throw new IOException
                ("Expected symmetric encrypted data, got : "+o.getClass());
        }
        PGPPBEEncryptedData pbedata = (PGPPBEEncryptedData) o;

        InputStream decoded = pbedata.getDataStream
            (new BcPBEDataDecryptorFactory
             (encpass, new BcPGPDigestCalculatorProvider()));
        return extractAndVerify(pbedata, decoded, signkey);
    }


    // Various methods that expect data to be present in a particular
    // way.
    private final static PGPOnePassSignature expectOPS(PGPObjectFactory f)
        throws IOException, PGPException
    {
        Object o = f.nextObject();
        if (!(o instanceof PGPOnePassSignatureList)) {
            throw new IOException
                ("Did not find signature header: "+o.getClass());
        }
        PGPOnePassSignatureList opsl = (PGPOnePassSignatureList) o;
        if (opsl.size() != 1) {
            throw new IOException
                ("Expected a single signature, got: "+opsl.size());
        }
        return opsl.get(0);
    }

    private final static PGPSignature expectSignature(PGPObjectFactory f)
        throws IOException, PGPException
    {
        Object o = f.nextObject();
        if (!(o instanceof PGPSignatureList)) {
            throw new IOException
                ("Did not find signature: "+o.getClass());
        }
        PGPSignatureList sl = (PGPSignatureList) o;
        if (sl.size() != 1) {
            throw new IOException
                ("Expected a single signature, got: "+sl.size());
        }
        return sl.get(0);
    }

    @SuppressWarnings("unchecked")
    private final static PGPPublicKeyRing realReadPublicKeyRing
        (InputStream inp)
        throws IOException, PGPException, SignatureException
    {
        PGPPublicKeyRingCollection pkrc =
            new PGPPublicKeyRingCollection(inp);
        if (pkrc.size() != 1) {
            throw new IOException("Unexpected number of key-rings: "+
                                  pkrc.size());
        }
        Iterator<PGPPublicKeyRing> it = pkrc.getKeyRings();
        PGPPublicKeyRing pkr = it.next();

        // verify signatures, etc.
        PGPPublicKey master = null;
        for (Iterator<PGPPublicKey> pki = pkr.getPublicKeys();
             pki.hasNext();) {
            PGPPublicKey cur = pki.next();
            if (cur.isMasterKey()) {
                if (master == null) {
                    checkMasterKey(cur);
                    master = cur;
                }
                else {
                    throw new PGPException("multiple master keys");
                }
            }
        }
        if (master == null) {
            throw new PGPException("no master key found");
        }

        PGPPublicKey subkey = null;
        for (Iterator<PGPPublicKey> pki = pkr.getPublicKeys();
             pki.hasNext();) {
            PGPPublicKey cur = pki.next();
            if (!cur.isMasterKey()) {
                if (subkey == null) {
                    checkSubKey(cur, master);
                    subkey = cur;
                }
                else {
                    throw new PGPException("multiple subkeys");
                }
            }
        }
        if (subkey == null) {
            throw new PGPException("no subkey found");
        }
        return pkr;
    }

    @SuppressWarnings("unchecked")
    private final static PGPSecretKeyRing realReadSecretKeyRing
        (InputStream inp, char[] pw)
        throws IOException, PGPException, SignatureException
    {
        PGPSecretKeyRingCollection skrc =
            new PGPSecretKeyRingCollection(inp);
        if (skrc.size() != 1) {
            throw new IOException("Unexpected number of key-rings: "+
                                  skrc.size());
        }
        Iterator<PGPSecretKeyRing> it = skrc.getKeyRings();
        PGPSecretKeyRing skr = it.next();

        // verify signatures, etc.
        PGPSecretKey master = null;
        for (Iterator<PGPSecretKey> ski = skr.getSecretKeys();
             ski.hasNext();) {
            PGPSecretKey cur = ski.next();
            if (cur.isMasterKey()) {
                if (master == null) {
                    checkMasterKey(cur.getPublicKey());
                    extractPrivateKey(cur, pw);
                    master = cur;
                }
                else {
                    throw new PGPException("multiple master keys");
                }
            }
        }
        if (master == null) {
            throw new PGPException("no master key found");
        }

        PGPSecretKey subkey = null;
        for (Iterator<PGPSecretKey> ski = skr.getSecretKeys();
             ski.hasNext();) {
            PGPSecretKey cur = ski.next();
            if (!cur.isMasterKey()) {
                if (subkey == null) {
                    checkSubKey(cur.getPublicKey(), master.getPublicKey());
                    extractPrivateKey(cur, pw);
                    subkey = cur;
                }
                else {
                    throw new PGPException("multiple subkeys");
                }
            }
        }
        if (subkey == null) {
            throw new PGPException("no subkey found");
        }
        return skr;
    }

    private final static PGPPrivateKey extractPrivateKey
        (PGPSecretKey sk, char[] pw)
        throws PGPException
    {
        if (sk.getKeyEncryptionAlgorithm() ==
            SymmetricKeyAlgorithmTags.NULL) {
            throw new PGPException
                ("Unwilling to accept unencrypted keys");
        }

        return sk.extractPrivateKey
            (new BcPBESecretKeyDecryptorBuilder
             (new BcPGPDigestCalculatorProvider()).build(pw));
    }

    @SuppressWarnings("unchecked")
    private final static void checkSubKey
        (PGPPublicKey subkey, PGPPublicKey master)
        throws PGPException,SignatureException
    {
        Iterator<PGPSignature> sigs = subkey.getSignatures();
        boolean ok = false;
        if (sigs != null) {
            // 
            while (sigs.hasNext()) {
                PGPSignature sig = sigs.next();

                if ((sig.getKeyID() != master.getKeyID()) ||
                    (sig.getSignatureType() != PGPSignature.SUBKEY_BINDING)) {
                    throw new PGPException
                        ("Disallowed signature on subkey");
                }
                sig.init(s_provider, master);
                ok = sig.verifyCertification(master, subkey);
                if (!ok) {
                    throw new PGPException("Subkey signature incorrect");
                }
            }
        }
        if (!ok) {
            throw new PGPException("Missing a binding signature for subkey");
        }
    }

    @SuppressWarnings("unchecked")
    private final static void checkMasterKey(PGPPublicKey master)
        throws PGPException, SignatureException
    {
        long vs = master.getValidSeconds();
        if (vs != 0) {
            long expire = master.getCreationTime().getTime()+(vs*1000);
            long now = System.currentTimeMillis();
            if (expire < now) {
                throw new PGPException
                    ("Sorry, this certificate expired on "+
                     new Date(expire));
            }
        }

        Iterator<String> uids = master.getUserIDs();
        String uid;
        // exactly one.
        if (uids.hasNext()) { uid = uids.next(); }
        else { throw new PGPException("Missing user-id packet."); }
        if (uids.hasNext()) {
            throw new PGPException("Only one user-id allowed.");
        }

        boolean ok = false;
        Iterator<PGPSignature> sigs = master.getSignatures();
        if (sigs != null) {
            while (sigs.hasNext()) {
                PGPSignature sig = sigs.next();
                // Only accept a very strict subset of signatures.
                if ((sig.getKeyID() != master.getKeyID()) ||
                    (sig.getSignatureType() !=
                     PGPSignature.POSITIVE_CERTIFICATION)) {
                    throw new PGPException
                        ("Disallowed signature on master key");
                }

                sig.init(s_provider, master);
                ok = sig.verifyCertification(uid, master);
                if (!ok) {
                    throw new PGPException("incorrect master self-signature");
                }
            }
        }
        if (!ok) {
            throw new PGPException("Missing master self-signature");
        }
    }

    private final static void pipeSignedBytes
        (byte[] inbytes, OutputStream out, int pgpAlgorithm,
         PGPPrivateKey privkey, String name, Date modtime)
        throws PGPException, IOException, SignatureException
    {
        // Dump 3 packets to out:
        //   one-pass signature header
        //   literal data
        //   signature

        PGPSignatureGenerator sGen =
            new PGPSignatureGenerator
            (new BcPGPContentSignerBuilder
             (pgpAlgorithm, HashAlgorithmTags.SHA256));
        sGen.init(PGPSignature.BINARY_DOCUMENT, privkey);

        // header packet
        sGen.generateOnePassVersion(false).encode(out);

        // literal data packet
        PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();
        OutputStream ldOut =
            ldGen.open
            (out, PGPLiteralData.BINARY, name, inbytes.length, modtime);
        ldOut.write(inbytes);
        ldGen.close();

        // update signature, and write packet.
        sGen.update(inbytes);
        sGen.generate().encode(out);
    }
    private final static BcPGPContentVerifierBuilderProvider s_provider =
        new BcPGPContentVerifierBuilderProvider();
}
