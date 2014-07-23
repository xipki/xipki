/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * @author Lijun Liao
 */

public class PasswordBasedEncryption
{
    private static final String CIPHER_ALGO = "PBEWITHSHA256AND256BITAES-CBC-BC";

    public static byte[] encrypt(byte[] plaintext, char[] password, int iterationCount, byte[] salt)
    throws GeneralSecurityException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
        pbeKeySpec.clearPassword();

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] cipherText, char[] password, int iterationCount, byte[] salt)
    throws GeneralSecurityException
    {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGO, "BC");
        SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, "BC");
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }
}
