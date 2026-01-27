// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.ExtraParams;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.EDDSA_PARAMS;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.wrapper.params.SIGN_ADDITIONAL_CONTEXT;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.security.HashAlgo;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;
/**
 * PKCS#11 params.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface P11Params {

  default CkMechanism toMechanism(long mechanism, ExtraParams extraParams)
      throws TokenException {
    CkParams paramObj;
    if (this instanceof P11Params.P11RSAPkcsPssParams) {
      P11Params.P11RSAPkcsPssParams param =
          (P11Params.P11RSAPkcsPssParams) this;
      paramObj = new RSA_PKCS_PSS_PARAMS(param.getHashAlgorithm(),
          param.getMaskGenerationFunction(), param.getSaltLength());
    } else if (this instanceof P11Params.P11ByteArrayParams) {
      paramObj = new ByteArrayParams(
          ((P11Params.P11ByteArrayParams) this).getBytes());
    } else if (this instanceof P11Params.P11EddsaParams) {
      P11Params.P11EddsaParams eddsaParams = (P11Params.P11EddsaParams) this;
      paramObj = new EDDSA_PARAMS(eddsaParams.prehash, eddsaParams.context);
    } else if (this instanceof P11Params.P11SignAdditionalContext) {
      P11Params.P11SignAdditionalContext sad =
          (P11Params.P11SignAdditionalContext) this;
      paramObj = new SIGN_ADDITIONAL_CONTEXT(sad.hedgeVariant, sad.context);
    } else {
      throw new TokenException(
          "unknown P11Parameters " + getClass().getName());
    }

    CkMechanism mech = new CkMechanism(mechanism, paramObj);
    mech.setExtraParams(extraParams);
    return mech;
  }

  class P11ByteArrayParams implements P11Params {

    private final byte[] bytes;

    public P11ByteArrayParams(byte[] bytes) {
      this.bytes = bytes;
    }

    public byte[] getBytes() {
      return bytes;
    }

  }

  class P11RSAPkcsPssParams implements P11Params {

    private final long hashAlgorithm;

    private final long maskGenerationFunction;

    private final int saltLength;

    public P11RSAPkcsPssParams(HashAlgo hashAlgo) {
      this.saltLength = hashAlgo.getLength();

      switch (hashAlgo) {
        case SHA1:
          this.hashAlgorithm = CKM_SHA_1;
          this.maskGenerationFunction = CKG_MGF1_SHA1;
          break;
        case SHA224:
          this.hashAlgorithm = CKM_SHA224;
          this.maskGenerationFunction = CKG_MGF1_SHA224;
          break;
        case SHA256:
          this.hashAlgorithm = CKM_SHA256;
          this.maskGenerationFunction = CKG_MGF1_SHA256;
          break;
        case SHA384:
          this.hashAlgorithm = CKM_SHA384;
          this.maskGenerationFunction = CKG_MGF1_SHA384;
          break;
        case SHA512:
          this.hashAlgorithm = CKM_SHA512;
          this.maskGenerationFunction = CKG_MGF1_SHA512;
          break;
        case SHA3_224:
          this.hashAlgorithm = CKM_SHA3_224;
          this.maskGenerationFunction = CKG_MGF1_SHA3_224;
          break;
        case SHA3_256:
          this.hashAlgorithm = CKM_SHA3_256;
          this.maskGenerationFunction = CKG_MGF1_SHA3_256;
          break;
        case SHA3_384:
          this.hashAlgorithm = CKM_SHA3_384;
          this.maskGenerationFunction = CKG_MGF1_SHA3_384;
          break;
        case SHA3_512:
          this.hashAlgorithm = CKM_SHA3_512;
          this.maskGenerationFunction = CKG_MGF1_SHA3_512;
          break;
        default:
          throw new IllegalStateException(
              "unsupported hash algorithm " + hashAlgo);
      }
    }

    public long getHashAlgorithm() {
      return hashAlgorithm;
    }

    public long getMaskGenerationFunction() {
      return maskGenerationFunction;
    }

    public int getSaltLength() {
      return saltLength;
    }

  }

  class P11EddsaParams implements P11Params {

    private final boolean prehash;

    private final byte[] context;

    public P11EddsaParams(boolean prehash, byte[] context) {
      this.prehash = prehash;
      this.context = context;
    }

    public boolean prehash() {
      return prehash;
    }

    public byte[] context() {
      return context;
    }
  }

  class P11SignAdditionalContext implements P11Params {

    private final long hedgeVariant;

    private final byte[] context;

    public P11SignAdditionalContext(byte[] context) {
      this(CKH_HEDGE_PREFERRED, context);
    }

    public P11SignAdditionalContext(long hedgeVariant, byte[] context) {
      this.hedgeVariant = hedgeVariant;
      this.context = context;
    }

    public long hedgeVariant() {
      return hedgeVariant;
    }

    public byte[] context() {
      return context;
    }
  }

}
