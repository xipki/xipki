// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.profile.ctrl.KeypairGenControl;
import org.xipki.security.KeySpec;

import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class BuilderUtil {

  public static KeypairGenControl createKeypairGenControl(
      KeypairGenMode keypairGenMode,
      AllowKeyMode allowedKeyMode) {
    if (keypairGenMode == null || keypairGenMode == KeypairGenMode.FORBIDDEM) {
      return KeypairGenControl.FORBIDDEN;
    } else if (keypairGenMode == KeypairGenMode.INHERITCA) {
      return KeypairGenControl.INHERIT_CA;
    } else if (keypairGenMode == KeypairGenMode.FIRST_ALLOWED_KEY) {
      KeySpec keyType;
      switch (allowedKeyMode) {
        case EC:
        case EC_SECP:
          keyType = KeySpec.SECP256R1;
          break;
        case RSA:
          keyType = KeySpec.RSA2048;
          break;
        case SM2:
          keyType = KeySpec.SM2P256V1;
          break;
        case EDDSA:
        case ED25519:
          keyType = KeySpec.ED25519;
          break;
        case ED448:
          keyType = KeySpec.ED448;
          break;
        case XDH:
        case X25519:
          keyType = KeySpec.X25519;
          break;
        case X448:
          keyType = KeySpec.X448;
          break;
        case MLDSA:
          keyType = KeySpec.MLDSA44;
          break;
        case MLKEM:
          keyType = KeySpec.MLKEM512;
          break;
        default:
          throw new IllegalStateException(
              "unknown AllowedKeyMode " + allowedKeyMode);
      }

      return new KeypairGenControl(keyType);
    } else {
      throw new IllegalStateException("shall not reach here");
    }
  }

  public static List<KeySpec> createKeyAlgorithmTypes(
      AllowKeyMode... allowKeyModes) {
    if (allowKeyModes == null || allowKeyModes.length == 0) {
      return null;
    }

    List<KeySpec> list = new LinkedList<>();
    for (AllowKeyMode keyMode : allowKeyModes) {
      switch (keyMode) {
        case RSA:
          list.add(KeySpec.RSA2048);
          list.add(KeySpec.RSA3072);
          list.add(KeySpec.RSA4096);
          break;
        case SM2:
          list.add(KeySpec.SM2P256V1);
          break;
        case EC:
          list.add(KeySpec.SECP256R1);
          list.add(KeySpec.SECP384R1);
          list.add(KeySpec.SECP521R1);
          list.add(KeySpec.BRAINPOOLP256R1);
          list.add(KeySpec.BRAINPOOLP384R1);
          list.add(KeySpec.BRAINPOOLP512R1);
          list.add(KeySpec.SM2P256V1);
          list.add(KeySpec.FRP256V1);
          break;
        case EC_SECP:
          list.add(KeySpec.SECP256R1);
          list.add(KeySpec.SECP384R1);
          list.add(KeySpec.SECP521R1);
          break;
        case XDH:
          list.add(KeySpec.X25519);
          list.add(KeySpec.X448);
          break;
        case X25519:
          list.add(KeySpec.X25519);
          break;
        case X448:
          list.add(KeySpec.X448);
          break;
        case EDDSA:
          list.add(KeySpec.ED25519);
          list.add(KeySpec.ED448);
          break;
        case ED25519:
          list.add(KeySpec.ED25519);
          break;
        case ED448:
          list.add(KeySpec.ED448);
          break;
        case MLDSA:
          list.add(KeySpec.MLDSA44);
          list.add(KeySpec.MLDSA65);
          list.add(KeySpec.MLDSA87);
          break;
        case MLKEM:
          list.add(KeySpec.MLKEM512);
          list.add(KeySpec.MLKEM768);
          list.add(KeySpec.MLKEM1024);
          break;
      }
    }

    return list;

  }

}
