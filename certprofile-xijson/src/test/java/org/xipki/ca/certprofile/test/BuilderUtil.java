// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.api.profile.ctrl.KeypairGenControl;
import org.xipki.security.KeySpec;

import java.util.ArrayList;
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
        case ALL_SIGN:
        case ALL_ENC:
        case ALL:
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
        case COMPSIG:
          keyType = KeySpec.MLDSA44_P256;
          break;
        case COMPKEM:
          keyType = KeySpec.MLKEM768_P256;
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
      list.addAll(createKeyAlgorithmTypes0(keyMode));
    }
    return list;
  }

  private static List<KeySpec> createKeyAlgorithmTypes0(AllowKeyMode keyMode) {
    List<KeySpec> list = new ArrayList<>();
    switch (keyMode) {
      case RSA:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isRSA()) {
            list.add(keySpec);
          }
        }
        break;
      case SM2:
        list.add(KeySpec.SM2P256V1);
        break;
      case EC:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isWeierstrassEC()) {
            list.add(keySpec);
          }
        }
        break;
      case EC_SECP:
        list.add(KeySpec.SECP256R1);
        list.add(KeySpec.SECP384R1);
        list.add(KeySpec.SECP521R1);
        break;
      case X25519:
        list.add(KeySpec.X25519);
        break;
      case X448:
        list.add(KeySpec.X448);
        break;
      case ED25519:
        list.add(KeySpec.ED25519);
        break;
      case ED448:
        list.add(KeySpec.ED448);
        break;
      case MLDSA:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isMldsa()) {
            list.add(keySpec);
          }
        }
        break;
      case MLKEM:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isMlkem()) {
            list.add(keySpec);
          }
        }
        break;
      case COMPSIG:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isCompositeMLDSA()) {
            list.add(keySpec);
          }
        }
        break;
      case COMPKEM:
        for (KeySpec keySpec : KeySpec.values()) {
          if (keySpec.isCompositeMLKEM()) {
            list.add(keySpec);
          }
        }
        break;
      default:
        List<AllowKeyMode> implies = keyMode.implies();
        if (implies != null && !implies.isEmpty()) {
          for (AllowKeyMode km : implies) {
            list.addAll(createKeyAlgorithmTypes0(km));
          }
        } else {
          throw new IllegalArgumentException("unknown keySpec " + keyMode);
        }
    }
    return list;
  }

}
