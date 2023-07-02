package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64Url;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

public class DummyMain {

  private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger(
      "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
          + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
          + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
          + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
      16);

  public static void main(String[] args) {
    try {
      String str = "eyJjc3IiOiJNSUlDaERDQ0FXd0NBUUF3RmpFVU1CSUdBMVVFQXd3TFpYaGhiWEJzWlM1dmNtY3dnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDbjdTLW12U2dqV3p5S2tMeG1hZWRhOU5nUkJWdW05NWwxeGtuZkxDN1ZrN25DblM1eXJGVlgyT201ZDk4bEpLQl9lMlB4UHF4ZWI3ZEIwcDV2R0JZajNEWHQ1WFB4WFhfUmNhUGFQRTE1aXVBcHV1VFN1eWg0cUpSNTRZMGRmQUVMLW8xX01XUVl5ZzZra2FIeFFmRE9nRm5ZSWRHbTFEWW5iYmJiX0o2eWthZWZrOUVrUWwzWFM4RXBiNFdUT05mXzB6RmxPUVF0WkYxdzdETVNyUE5pZ3NDWmhURW5CaVNGYzVxckFscFhHUnRHSklIMU9TZGRxTVplR0hGcW5JQzJGUEJIR194bm9DWkM1eVI5QmYzN0dfc1U1c3d4eGpvUjFzX0ZQS296aFZHSTlOdUI1LXNRT2FfZFplSEcwRXFBaVAxVXMyZG9RQkR0ZXhsaG1CdzNBZ01CQUFHZ0tUQW5CZ2txaGtpRzl3MEJDUTR4R2pBWU1CWUdBMVVkRVFRUE1BMkNDMlY0WVcxd2JHVXViM0puTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCVjBhQ24xY0xxZzNvTkxTS0tZTE4yMkFWS1dPRWltalRIX29CSGcxOGpXVlJlSHNBaU1WbWVnNFRBQWVwakR2Z1ctRE5NOG1zTTk5OGVvLUpEUHpONVA4eEVkSjVRU1VNazZOdGNQbVAtWDlPVlhQdF92M2VFNUhLMjRpY0t6QU1VSzF2S082TUc4VU9wbjR4Y1ZyTEZJWk9OYllqSnRlcE1yR25IRHJLUzZOSjlLSWNHU3pUZXdsZXZWNUNNM0JNS2RRMTlUQXk0dXBLQTRiUHZ0ODhZRUlsRjlndzZPN2NaX2phWW1sVUpPcG9jdjJES1U3YzA1d0NzeTZMNExvbkhxbkxXWk8zVnhlSy1mZzFMR1diXzVSNXRmbVg0QVFMeHlUajUtOHpTRmcwdVM2UW5za3YyODR1MF91U0wzaWl0VzlKX0t3Um9oV29uRkFhMkMydXoifQ";
      byte[] csrBytes = Base64Url.decodeFast(str);
      CertificationRequest csr = CertificationRequest.getInstance(csrBytes);
      RSAPublicKey pk = (RSAPublicKey) KeyUtil.generatePublicKey(csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
      BigInteger modulus = pk.getModulus();
        if (!modulus.gcd(SMALL_PRIMES_PRODUCT).equals(BigInteger.ONE)) {
          throw new IllegalArgumentException("RSA modulus has a small prime factor");
        }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
