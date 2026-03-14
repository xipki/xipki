// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.pkcs11.wrapper.ExtraParams;
import org.xipki.pkcs11.wrapper.params.ByteArrayParams;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.params.EDDSA_PARAMS;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_OAEP_PARAMS;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;
import org.xipki.pkcs11.wrapper.params.SIGN_ADDITIONAL_CONTEXT;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.security.HashAlgo;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;
/**
 * PKCS#11 params.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class  P11Params {

  protected abstract CkParams toCkParams();

  public CkMechanism toMechanism(long mechanism, ExtraParams extraParams) {
    CkParams paramObj = toCkParams();
    CkMechanism mech = new CkMechanism(mechanism, paramObj);
    mech.setExtraParams(extraParams);
    return mech;
  }

  public static class P11ByteArrayParams extends P11Params {

    private final byte[] bytes;

    public P11ByteArrayParams(byte[] bytes) {
      this.bytes = bytes;
    }

    @Override
    protected CkParams toCkParams() {
      return new ByteArrayParams(bytes);
    }

  }

  private abstract static class P11RSAPkcsPssOrOaepParams extends P11Params {

    protected final long hashAlgorithm;

    protected final long maskGenerationFunction;

    public P11RSAPkcsPssOrOaepParams(HashAlgo hashAlgo) {
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
          throw new IllegalStateException("unsupported hash algorithm " + hashAlgo);
      }
    }

  }

  public static class P11RSAPkcsPssParams extends P11RSAPkcsPssOrOaepParams {

    private final int saltLength;

    public P11RSAPkcsPssParams(HashAlgo hashAlgo) {
      super(hashAlgo);
      this.saltLength = hashAlgo.length();
    }

    @Override
    protected CkParams toCkParams() {
      return new RSA_PKCS_PSS_PARAMS(hashAlgorithm, maskGenerationFunction, saltLength);
    }

  }

  public static class P11RSAPkcsOaepParams extends P11RSAPkcsPssOrOaepParams {

    private final long source;

    private final byte[] sourceData;

    public P11RSAPkcsOaepParams(HashAlgo hashAlgo, long source, byte[] sourceData) {
      super(hashAlgo);
      this.source = source;
      this.sourceData = sourceData;
    }

    @Override
    protected CkParams toCkParams() {
      return new RSA_PKCS_OAEP_PARAMS(hashAlgorithm, maskGenerationFunction, source, sourceData);
    }

  }

  public static class P11EddsaParams extends P11Params {

    private final boolean prehash;

    private final byte[] context;

    public P11EddsaParams(boolean prehash, byte[] context) {
      this.prehash = prehash;
      this.context = context;
    }

    @Override
    protected CkParams toCkParams() {
      return new EDDSA_PARAMS(prehash, context);
    }

  }

  public static class P11SignAdditionalContext extends P11Params {

    private final long hedgeVariant;

    private final byte[] context;

    public P11SignAdditionalContext(byte[] context) {
      this(CKH_HEDGE_PREFERRED, context);
    }

    public P11SignAdditionalContext(long hedgeVariant, byte[] context) {
      this.hedgeVariant = hedgeVariant;
      this.context = context;
    }

    @Override
    protected CkParams toCkParams() {
      return new SIGN_ADDITIONAL_CONTEXT(hedgeVariant, context);
    }

  }

  public static class P11Ecdh1DeriveParams extends P11Params {

    private final long kdf;

    private final byte[] sharedData;

    private final byte[] publicData;

    public P11Ecdh1DeriveParams(long kdf, byte[] sharedData, byte[] publicData) {
      this.kdf = kdf;
      this.sharedData = sharedData;
      this.publicData = publicData;
    }

    @Override
    protected CkParams toCkParams() {
      return new ECDH1_DERIVE_PARAMS(kdf, sharedData, publicData);
    }

  }

}
