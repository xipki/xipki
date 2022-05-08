/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.qa.ca;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.xipki.security.EdECConstants;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.xipki.util.Args.notNull;

/**
 * SubjectPublicKeyInfo entry for benchmark enrollment test.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaEnrollBenchKeyEntry {

  public static final class RSAKeyEntry extends CaEnrollBenchKeyEntry {

    private static final String N_1024 =
        "ALI9Q2yy0KKsfuJw6tOfXBY3aJevCKyCQYM4DWK0eL1noqh6Uk6Ro3AsLVcoJDlZ"
        + "xCOdqhwq41jsgrj5iEvf9tagNTnsLLscGEUkHWZDJIF9uQd5ISjFtcdaEGdv2v5K"
        + "f48Drcg7o+c+LtR5ZNmtaEySUtjRFYh3icMzoh6zzA/z";

    private static final String N_2048 =
        "AMQdbyhdRJvPE7WoyLBucRfELTPyMZZ3fEpIN+BiALpxfi2AAu4N9kvi/MT2xpfI"
        + "hdNHLDLX02tECy/XDdQiEKKJ2mfDr29me72yvO7PtpxUaPfyd6vzBEfGQqal42qZ"
        + "U1pmIgJm0jE4Gl4EdfyXEHsnekrLTjHiLnSr2WhlL+yY9xwO589VQIYziG53SbUM"
        + "cu0eMxzgfwT7UXKvPvbfzJjgWiin8PozENy+8yFzkCUOUK2uFa5iJPky8o5WSsqs"
        + "Q/nH7Jq0MyQaG58M+//0g3glXirbtX+BARGR130VeMAnxMktLc4VdZ+I75wNxLap"
        + "ksE19yQ4Ta0JRzGMwVZR7Pk=";

    private static final String N_3072 =
        "AL1F3ms6ImUDkIVEgjqM9NUQ2NpImvoNbvwq+zRLTvamIegsapwDi0cLkdD47vR9"
        + "bM50zuKX0+4FzJZe8MWQheTmSVbdF8EcORGh1OXYidmV9zFOrym961sBCvJ1x1W3"
        + "p00kyqi55gONxklvbK2MYAifoUIqe0L6TS4W0eJrWB25JuLP8U09xZQRFm1qAiSQ"
        + "JsZSfxcZfOtVOYp6oDsMqhk3RNKrpw/UqtfcRjYG+ZhccDZcmLS/UmHPHRuDsgCA"
        + "AebH3bDEqbQZ8hFqVdRDGWnIirLJ67+0e+3j6UjoI4ybSwy9O9g36rooC5bCboEA"
        + "46r03BiX28JMveHip689b+RAHgKy95Yd5eFIWYQBNAmUNZ+9hq4KTvrSb7ysge7d"
        + "qVY5nnsnmpXFyqy51dlem4npXAM73a9vLuEOioSOOqBwNDXyxBaETgqH4AWBdNK/"
        + "aSvwu2cUjFCKfds2Ycik+6pfu4gid2Pp5j2lXMvvtaIQNx88e2UTo8Jn+D+baFBX"
        + "uw==";

    private static final String N_4096 =
        "AMO03X0Vp9Diw8KW9zeuDSICAnohZT98o6lnJJR1pUZIPINOMuf/SG2vVR0Uv/cx"
        + "yY/8Fvn1ySzG0OjYE4mH9l1C4bvaiiKEMT1liX4WK2ndFFtwG3HmueRThn1uq2"
        + "y5WCUOZkD2/5atrcJfzWiox30zAikyLkOZ6kTY0anZ3UraF4Zj9Rvkpn4NMlUx"
        + "txN1CKrW+Cn1D2lPhGFRLB9joNOtlpt6zqv/Dyvfxc/6hnSQeQLd20bozbfKKs"
        + "Hvj+PU1wI2rHVI5XtS7efZCzvMzJ05wVZgTnQldxHbjw397u1uavsNncwmCcsH"
        + "crbvRWJDvvWvQWUOoG4KgMcGRbX0fdzMwntUMvO7A9AIlb4KtcPicpIQGYsiTe"
        + "WxM+Bpawo2a1ENy+HahP9rCU8i+bWRR8zsEhmuT6E7BK6/VmHU6NKbjkMIjIXN"
        + "GvULvVX6b1+hBOinVTm4ly+33ZK7zsl0nML5e0c7jFvq4XPvpi42kkP1RNjle0"
        + "zNIHdtWkRw/+lYpKmkuAU2gvu/iZXkvZBw9ncqABsRhbhfiwQlODOaF9h20rUW"
        + "HArzIk6vrsRyMjm5U9bKVimYaalQCmq1Uq49EYazIa31e5uDDMnbfcmMoPyi9Z"
        + "5jQAVfm+tWuvM+S118s3d/mCpoX62O3gLaHNpPpD8CHoOagGcqthk+9/wWarhR";

    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65535);

    private final SubjectPublicKeyInfo spki;

    public RSAKeyEntry(int keysize)
        throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalArgumentException("invalid RSA keysize " + keysize);
      }

      AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(
          PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

      String modulusStr;
      if (keysize == 1024 || keysize == 2048 || keysize == 3072 || keysize == 4096) {
        if (keysize == 1024) {
          modulusStr = N_1024;
        } else if (keysize == 2048) {
          modulusStr = N_2048;
        } else if (keysize == 3072) {
          modulusStr = N_3072;
        } else { // if (keysize == 4096) {
          modulusStr = N_4096;
        }
        BigInteger modulus = base64ToInt(modulusStr);
        this.spki = new SubjectPublicKeyInfo(keyAlgId,
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(modulus, PUBLIC_EXPONENT));
      } else {
        KeyPairGenerator kp = KeyPairGenerator.getInstance("RSA");
        kp.initialize(keysize);
        RSAPublicKey publicKey = (RSAPublicKey) kp.generateKeyPair().getPublic();
        this.spki = new SubjectPublicKeyInfo(keyAlgId,
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(
                publicKey.getModulus(), publicKey.getPublicExponent()));
      }
    } // constructor

    private static BigInteger base64ToInt(String base64Str) {
      return new BigInteger(1, Base64.decode(base64Str));
    }

    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
      return spki;
    }

  } // class RSAKeyEntry

  public static final class DSAKeyEntry extends CaEnrollBenchKeyEntry {

    private static final String P_1024 =
        "AM/6AjYLnnzRa99zmdhuMmikFKF/HhotHagBxoHlT4alq415sX94psaJPI3D5+/e"
        + "YUaZbnFMn/IEBh6YyEL4zPQs4xOYdcNoMJ6XccGelEHjVWDvocf00L417XiTJObM"
        + "UVHgFrkTPZ7G/mDBFMQ1WVrSSwnjPPDSCkIRiiGiCQqv";

    private static final String Q_1024 = "ANMDutPywwIBAbqpSxN8CAvbPkaL";

    private static final String G_1024 =
        "AcFvVWWRJlZsT2xCtto0gZj6QyaVAVJmvkZinCm2kafbFPQ+MLeZJKk3mvCaq2i8"
        + "DPptJ5LC1FaaE+Is4rhX0BcW5/rxxSk6JVboakH48KEg5nZvzphMNe9mC2bYV29z"
        + "BbyiYvs9v7EhAI7bKlvOaAb6XyB//fUh1+GYzP15HOw=";

    private static final String Y_1024 =
        "AMjz/ko+WVNXbLo7ixe+iIU2OpgngYIaSZQkbFFQ6E/ePlmgPlFY9gOV7CrjKYfn"
        + "MgU33SZHipa7Zo6LmgjNZ6VE2FE8PGE+CHM+XZMQlZdOtKZLMfRWUdYfUZ5D7j+1"
        + "3HlpW2ahfeClF5xuhwjcTDm7VdxZ+rVscp+QzF7Je35p";

    private static final String P_2048 =
        "ANAwGdtm8DJ6YHsC9A9c5bmg8saK4TShCmWoC0sLRwaueN/thcXQKjG4qNQu1BiR"
        + "wIGwlPqbX5F+i/kILuJ4xvcoffMsLZG9WoI8bG5Y+Ld9KWOJ/KDiYjdX5R9flbmq"
        + "gnMBUbscsLMStNBaHFZYe58S4uClVS6v7poi6s3e/B3ryvWPG4zIamFxV72DmSWo"
        + "nArfljTleJ/pVqlWW5WOTqXjk11ab53PSJGWPAyhfgZWhHTwsKt+HgemrA8D55us"
        + "vDVPhYNsnEy4FtJEbIJSsIKO4qGrhDA2mZeH30EXhZx83HWRML0GIP+tDguBN+hI"
        + "w7G9DpwQQL+f4lowf9rde38=";

    private static final String Q_2048 = "AO236rjUtJKK0CDLx+koJmwrX4xzffhW/hdqCOb8eOmV";

    private static final String G_2048 =
        "ALsVY3D6QRDnBiwfrbl4Br9wE5D9RZlPt6lUYmOIQFptcD1RWP0ZuajmDQ90FLJ/"
        + "jamGgqeIY+ZyA0UZqDcDtfrIB0sOML7xIqqUyTxV/UiIHnWVf9Xa9JGUWrUoqvVG"
        + "qiDI1G0OcIuBykDAHTUo0J54TKZP0DMILkwO0kqf+SM/mH4Q1qxV3RfRDUqc3v9s"
        + "/LgmshkkBsIapsh5AADA2GAoHnrLlgimgJS4zKoytCYYGtL0NqN4vyGiIQaeoOv4"
        + "JRwZ+gQsy7OA0nkDRWnAFsPOnPxQqsEGmfE8VGzXrHl42jcavPuJ1o3CCeMq30D0"
        + "VbEuwEMCUNBcjHTEpF0jnqs=";

    private static final String Y_2048 =
        "Pmn2UvUGcvhAwl57D86OPUdhiPJr4qaBNy9GAkUca4nkoQthP90dhvqB6b4FvJBr"
        + "jsWoPVQSxW+pX2vfbjscQMm4Kt5zaqeHnV/Rod4l5VeW7sqoRqBR7nzlke+xHkT0"
        + "wM3XkCp2E6BTAhT0qtp05w6onOoWIMv5Ydd04xwNB8lFF+A2uJrt3QlHXHvRW1no"
        + "Sf7bRDWC6JKLMRd+G0H8USMMT7UNUgen1lXbIH0q1GDph0z1MZkbUwewE/dG6KBL"
        + "3Km1hBmuWyUrqHLznKYPwhmcOqWpTGn2PJrmdEJdjhdhwpWT1POhiyP+YxxbFNv/"
        + "Kjkdw4wQAVloP0QZ4wH/IA==";

    private static final String P_3072 =
        "AOcper98q/F5dOpeZMTAxQiD3Sptsr0b19WMMwO+/P0YqjiS1LNqhX2ULuCv/oD1"
        + "TtgfRx5bNhsg4jA+mLtGHZAO2nGrF9fwlyxyv5gcx4D6WfDaLx1ZVGGcux8PlgLz"
        + "dshN10t6Icyl28Ky/G8HOFwu7kmHSw6fujsCqW0CvjiRW+sQ9N2Fuzjivg9axCyL"
        + "MtFLXUcQuIyHhlQWSQyrQkhAG0qLfLWpzM0BdWpL0hDSKgjOTNvYphRquqdzn90g"
        + "bXTwcQQdtuiQWg6WGhAz7feyuATmhESE2i2P5LV9LQGBG6j3zfU3ITmyexb4rFbp"
        + "gRSIWZ0nrs5uQ0lYZgUyr+dnzFnNqYZB7aNw5cFR5TWKcxTx0yp9kMMjjZSiQQc2"
        + "TVm254f6rztbERjU7HXxPFROujufBoTeBj0ayNxVJRIBs6XgSpE7/Gw3OJWJVMYT"
        + "5iA0MZv0Vs+WKdHoCKCZ8mfZbIisxCpFV8PW9/Xz6T59rBJxs51ZdwwyHz/EB7es"
        + "EQ==";

    private static final String Q_3072 = "ALQa/gl8UpkX42IsgfnihnQDS+NQ5US6eYGDz34guCib";

    private static final String G_3072 =
        "FyAOku6IrTU1iI6S0gl3soIF3mRbA/WiKpXu4ZCOdf9fHA12XtXPWRc7jaFBZucp"
        + "uxYtmDeUwCZRFX+HWpkptVv6LT8OIDbCFFfJlo6i0d1ulq9ybOLtcWXlqIcp4Z0v"
        + "LbFcxUr79CYp/mwdXzMwD+v7GFTa6feJdQENEfnwOGLUItOm+6OBcft+94xvDCmx"
        + "tfYYkgEaFvRFjVKy+9kDuf6OfFKM0RDX4tvvpPwpXdYghjk6C/9e0jqloW20DhsW"
        + "fBDmhp5cPSkjUDDSOz0JrOvT7MBeqefez6PbgMywZFiY+iBOZiIay2o5tI2uOaGq"
        + "z1K/1xo7tXMlZu0wFuxtwrThFbmbGIXAMCC4hNeW4hFKDRnYZtnRKChhh3gNx3eO"
        + "/58as/UIa8ApnjvG9tLpYtmlfJlgzlmEAuuB08qMg+T9tUjKQZWgEOiT6INFZS0P"
        + "mbSZgzJACYY6dMnywnne97TrgCccXuoTRV3derD91tU6lhfR5B4ZADXVClNrf7Nl";

    private static final String Y_3072 =
        "aiFUID1NF6SllNJf2RDMik1rU2A5VQc4pLw8wfvxG2WXCSTeuWnDB7b3HBtQOwox"
        + "lYaDQnKBEcly61aVbLKP+TD8dngJQNlr42M07u2drT2ADbk3cLWQ8lk27LBWjntX"
        + "oXduWz2onw1FEdh2nJSTkHZGBaQpUt8vwxB3IWoGsaazOKLnm/rZlK9g9Rs0RCXA"
        + "8KViQEUuAU1h/tt2bEFgOECQ6efm3oBeG3TfpstMud7QaGyyFnTgRxrZQpC1Et3D"
        + "e8TVvIy3uUjnOjGDVV8qGVjsI3J9zX3w5TbTDB4+lbMpc9/oMd26veU+8+7GY5Sz"
        + "iEPTcZF38POgm8I9Nxe5gxtiNJyOMQZC20rnffJljVLe8L1LrXPj0MJfVZMLXiyz"
        + "SLFRUj7ZpN4rzgQYkB0ETN40DFFk3a2gC9E2g+EdksAW0h+IAElikX4Q4Ja0kzXu"
        + "wJfVmq5g/Sp4ysk+JTzAl6r4T1dDr9BXpGgRdYdgwE/2RTMfunqTcUYlV752sbvy";

    private SubjectPublicKeyInfo spki;

    public DSAKeyEntry(int plength)
        throws Exception {
      if (plength == 1024) {
        init(P_1024, Q_1024, G_1024, Y_1024);
      } else if (plength == 2048) {
        init(P_2048, Q_2048, G_2048, Y_2048);
      } else if (plength == 3072) {
        init(P_3072, Q_3072, G_3072, Y_3072);
      } else {
        if (plength % 1024 != 0) {
          throw new IllegalArgumentException("invalid DSA pLength " + plength);
        }

        int qlength = (plength >= 2048) ? 256 : 160;
        KeyPair kp = KeyUtil.generateDSAKeypair(plength, qlength, new SecureRandom());
        DSAPublicKey pk = (DSAPublicKey) kp.getPublic();

        init(pk.getParams().getP(), pk.getParams().getQ(), pk.getParams().getG(), pk.getY());
      }
    }

    private static BigInteger base64ToInt(String base64Str) {
      return new BigInteger(1, Base64.decode(base64Str));
    }

    private void init(String p, String q, String g, String y)
        throws IOException {
      init(base64ToInt(p), base64ToInt(q), base64ToInt(g), base64ToInt(y));
    }

    private void init(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
        throws IOException {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new ASN1Integer(p));
      vec.add(new ASN1Integer(q));
      vec.add(new ASN1Integer(g));
      ASN1Sequence dssParams = new DERSequence(vec);
      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams);
      this.spki = new SubjectPublicKeyInfo(algId, new ASN1Integer(y));
    }

    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
      return spki;
    }

  } // class DSAKeyEntry

public static final class ECKeyEntry extends CaEnrollBenchKeyEntry {

    private final SubjectPublicKeyInfo spki;

    public ECKeyEntry(final ASN1ObjectIdentifier curveOid)
        throws Exception {
      notNull(curveOid, "curveOid");
      KeyPair keypair;

      if (EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)) {
        keypair = KeyUtil.generateEdECKeypair(curveOid, null);
        this.spki = KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
      } else {
        String curveName = AlgorithmUtil.getCurveName(curveOid);
        if (curveName == null) {
          curveName = curveOid.getId();
        }

        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
            curveOid);

        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        kpgen.initialize(spec);
        KeyPair kp = kpgen.generateKeyPair();

        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int orderBitLength = pub.getParams().getOrder().bitLength();
        byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), orderBitLength);
        spki = new SubjectPublicKeyInfo(algId, keyData);
      }
    }

    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
      return spki;
    }

  } // class ECKeyEntry

  public abstract SubjectPublicKeyInfo getSubjectPublicKeyInfo();

}
