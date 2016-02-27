// #THIRDPARTY# BouncyCastle

/*
 * Copied from BouncyCastle under license MIT
 */

package org.xipki.commons.security.impl.bcext;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

/**
 * Copied from BouncyCastle under license MIT
 *
 */

public class BCRSAPrivateKey implements RSAPrivateKey, PKCS12BagAttributeCarrier {

    static final long serialVersionUID = 5110188922551353628L;

    private static final BigInteger ZERO = BigInteger.valueOf(0);

    protected BigInteger modulus;

    protected BigInteger privateExponent;

    private transient PKCS12BagAttributeCarrierImpl attrCarrier =
            new PKCS12BagAttributeCarrierImpl();

    protected BCRSAPrivateKey() {
    }

    public BCRSAPrivateKey(
            final RSAKeyParameters key) {
        this.modulus = key.getModulus();
        this.privateExponent = key.getExponent();
    }

    public BCRSAPrivateKey(
            final RSAPrivateKeySpec spec) {
        this.modulus = spec.getModulus();
        this.privateExponent = spec.getPrivateExponent();
    }

    public BCRSAPrivateKey(
            final RSAPrivateKey key) {
        this.modulus = key.getModulus();
        this.privateExponent = key.getPrivateExponent();
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                        new org.bouncycastle.asn1.pkcs.RSAPrivateKey(getModulus(),
                        ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
    }

    public boolean equals(
            final Object o) {
        if (!(o instanceof RSAPrivateKey)) {
            return false;
        }

        if (o == this) {
            return true;
        }

        RSAPrivateKey key = (RSAPrivateKey) o;

        return getModulus().equals(key.getModulus())
            && getPrivateExponent().equals(key.getPrivateExponent());
    }

    public int hashCode() {
        return getModulus().hashCode() ^ getPrivateExponent().hashCode();
    }

    public void setBagAttribute(
            final ASN1ObjectIdentifier oid,
            final ASN1Encodable attribute) {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
            final ASN1ObjectIdentifier oid) {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration<?> getBagAttributeKeys() {
        return attrCarrier.getBagAttributeKeys();
    }

    private void readObject(
            final ObjectInputStream in)
    throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
            final ObjectOutputStream out)
    throws IOException {
        out.defaultWriteObject();
    }

}
