// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * This interface holds constants of the constants defined in pkcs11t.h.
 *
 * @author Lijun Liao (xipki)
 */
public final class PKCS11T {

  /* some special values for certain CK_ULONG variables */
  public static final long CK_UNAVAILABLE_INFORMATION         = ~0L;
  public static final long CK_EFFECTIVELY_INFINITE            = 0x0L;

  /* The following value is always invalid if used as a session
   * handle or object handle
   */
  public static final long CK_INVALID_HANDLE                  = 0x0L;

  /* flags: bit flags that provide capabilities of the slot
   *      Bit Flag              Mask        Meaning
   */
  public static final long CKF_TOKEN_PRESENT                  = 0x00000001L;
  public static final long CKF_REMOVABLE_DEVICE               = 0x00000002L;
  public static final long CKF_HW_SLOT                        = 0x00000004L;

  /* The flags parameter is defined as follows:
   *      Bit Flag                    Mask        Meaning
   */
  public static final long CKF_RNG                            = 0x00000001L;
  public static final long CKF_WRITE_PROTECTED                = 0x00000002L;
  public static final long CKF_LOGIN_REQUIRED                 = 0x00000004L;
  public static final long CKF_USER_PIN_INITIALIZED           = 0x00000008L;

  /* CKF_RESTORE_KEY_NOT_NEEDED.  If it is set,
   * that means that *every* time the state of cryptographic
   * operations of a session is successfully saved, all keys
   * needed to continue those operations are stored in the state
   */
  public static final long CKF_RESTORE_KEY_NOT_NEEDED         = 0x00000020L;

  /* CKF_CLOCK_ON_TOKEN.  If it is set, that means
   * that the token has some sort of clock.  The time on that
   * clock is returned in the token info structure
   */
  public static final long CKF_CLOCK_ON_TOKEN                 = 0x00000040L;

  /* CKF_PROTECTED_AUTHENTICATION_PATH.  If it is
   * set, that means that there is some way for the user to login
   * without sending a PIN through the Cryptoki library itself
   */
  public static final long CKF_PROTECTED_AUTHENTICATION_PATH  = 0x00000100L;

  /* CKF_DUAL_CRYPTO_OPERATIONS.  If it is true,
   * that means that a single session with the token can perform
   * dual simultaneous cryptographic operations (digest and
   * encrypt; decrypt and digest; sign and encrypt; and decrypt
   * and sign)
   */
  public static final long CKF_DUAL_CRYPTO_OPERATIONS         = 0x00000200L;

  /* CKF_TOKEN_INITIALIZED. If it is true, the
   * token has been initialized using C_InitializeToken or an
   * equivalent mechanism outside the scope of PKCS #11.
   * Calling C_InitializeToken when this flag is set will cause
   * the token to be reinitialized.
   */
  public static final long CKF_TOKEN_INITIALIZED              = 0x00000400L;

  /* CKF_SECONDARY_AUTHENTICATION. If it is
   * true, the token supports secondary authentication for
   * private key objects.
   */
  public static final long CKF_SECONDARY_AUTHENTICATION       = 0x00000800L;

  /* CKF_USER_PIN_COUNT_LOW. If it is true, an
   * incorrect user login PIN has been entered at least once
   * since the last successful authentication.
   */
  public static final long CKF_USER_PIN_COUNT_LOW             = 0x00010000L;

  /* CKF_USER_PIN_FINAL_TRY. If it is true,
   * supplying an incorrect user PIN will it to become locked.
   */
  public static final long CKF_USER_PIN_FINAL_TRY             = 0x00020000L;

  /* CKF_USER_PIN_LOCKED. If it is true, the
   * user PIN has been locked. User login to the token is not
   * possible.
   */
  public static final long CKF_USER_PIN_LOCKED                = 0x00040000L;

  /* CKF_USER_PIN_TO_BE_CHANGED. If it is true,
   * the user PIN value is the default value set by token
   * initialization or manufacturing, or the PIN has been
   * expired by the card.
   */
  public static final long CKF_USER_PIN_TO_BE_CHANGED         = 0x00080000L;

  /* CKF_SO_PIN_COUNT_LOW. If it is true, an
   * incorrect SO login PIN has been entered at least once since
   * the last successful authentication.
   */
  public static final long CKF_SO_PIN_COUNT_LOW               = 0x00100000L;

  /* CKF_SO_PIN_FINAL_TRY. If it is true,
   * supplying an incorrect SO PIN will it to become locked.
   */
  public static final long CKF_SO_PIN_FINAL_TRY               = 0x00200000L;

  /* CKF_SO_PIN_LOCKED. If it is true, the SO
   * PIN has been locked. SO login to the token is not possible.
   */
  public static final long CKF_SO_PIN_LOCKED                  = 0x00400000L;

  /* CKF_SO_PIN_TO_BE_CHANGED. If it is true,
   * the SO PIN value is the default value set by token
   * initialization or manufacturing, or the PIN has been
   * expired by the card.
   */
  public static final long CKF_SO_PIN_TO_BE_CHANGED           = 0x00800000L;

  public static final long CKF_ERROR_STATE                    = 0x01000000L;

  /* Security Officer */
  public static final long CKU_SO                             = 0x0L;
  /* Normal user */
  public static final long CKU_USER                           = 0x1L;
  /* Context specific */
  public static final long CKU_CONTEXT_SPECIFIC               = 0x2L;

  public static final long CKS_RO_PUBLIC_SESSION              = 0x0L;
  public static final long CKS_RO_USER_FUNCTIONS              = 0x1L;
  public static final long CKS_RW_PUBLIC_SESSION              = 0x2L;
  public static final long CKS_RW_USER_FUNCTIONS              = 0x3L;
  public static final long CKS_RW_SO_FUNCTIONS                = 0x4L;

  /* The flags are defined in the following table:
   *      Bit Flag                Mask        Meaning
   */
  public static final long CKF_RW_SESSION                     = 0x00000002L;
  public static final long CKF_SERIAL_SESSION                 = 0x00000004L;
  public static final long CKF_ASYNC_SESSION                  = 0x00000008L;

  /* The following classes of objects are defined: */
  public static final long CKO_DATA                           = 0x00000000L;
  public static final long CKO_CERTIFICATE                    = 0x00000001L;
  public static final long CKO_PUBLIC_KEY                     = 0x00000002L;
  public static final long CKO_PRIVATE_KEY                    = 0x00000003L;
  public static final long CKO_SECRET_KEY                     = 0x00000004L;
  public static final long CKO_HW_FEATURE                     = 0x00000005L;
  public static final long CKO_DOMAIN_PARAMETERS              = 0x00000006L;
  public static final long CKO_MECHANISM                      = 0x00000007L;
  public static final long CKO_OTP_KEY                        = 0x00000008L;
  public static final long CKO_PROFILE                        = 0x00000009L;

  public static final long CKO_VENDOR_DEFINED                 = 0x80000000L;

  /* the following key types are defined: */
  public static final long CKK_RSA                            = 0x00000000L;
  public static final long CKK_DSA                            = 0x00000001L;
  public static final long CKK_EC                             = 0x00000003L;
  public static final long CKK_GENERIC_SECRET                 = 0x00000010L;
  public static final long CKK_DES                            = 0x00000013L;
  public static final long CKK_DES2                           = 0x00000014L;
  public static final long CKK_DES3                           = 0x00000015L;
  public static final long CKK_AES                            = 0x0000001FL;

  /* the following definitions were added in the 2.3 header file,
   * but never defined in the spec. */
  public static final long CKK_SHA_1_HMAC                     = 0x00000028L;
  public static final long CKK_SHA256_HMAC                    = 0x0000002BL;
  public static final long CKK_SHA384_HMAC                    = 0x0000002CL;
  public static final long CKK_SHA512_HMAC                    = 0x0000002DL;
  public static final long CKK_SHA224_HMAC                    = 0x0000002EL;

  public static final long CKK_CHACHA20                       = 0x00000033L;
  public static final long CKK_SHA3_224_HMAC                  = 0x00000036L;
  public static final long CKK_SHA3_256_HMAC                  = 0x00000037L;
  public static final long CKK_SHA3_384_HMAC                  = 0x00000038L;
  public static final long CKK_SHA3_512_HMAC                  = 0x00000039L;
  public static final long CKK_EC_EDWARDS                     = 0x00000040L;
  public static final long CKK_EC_MONTGOMERY                  = 0x00000041L;
  public static final long CKK_HKDF                           = 0x00000042L;

  public static final long CKK_SHA512_224_HMAC     = 0x00000043L;
  public static final long CKK_SHA512_256_HMAC     = 0x00000044L;
  public static final long CKK_SHA512_T_HMAC       = 0x00000045L;
  public static final long CKK_HSS                 = 0x00000046L;

  public static final long CKK_XMSS                = 0x00000047L;
  public static final long CKK_XMSSMT              = 0x00000048L;
  public static final long CKK_ML_KEM             = 0x00000049L;
  public static final long CKK_ML_DSA             = 0x0000004aL;
  public static final long CKK_SLH_DSA            = 0x0000004bL;

  public static final long CKK_VENDOR_DEFINED                 = 0x80000000L;

  /* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
   * consists of an array of values.
   */
  public static final long CKF_ARRAY_ATTRIBUTE                = 0x40000000L;

  /* The following attribute types are defined: */
  public static final long CKA_CLASS                          = 0x00000000L;
  public static final long CKA_TOKEN                          = 0x00000001L;
  public static final long CKA_PRIVATE                        = 0x00000002L;
  public static final long CKA_LABEL                          = 0x00000003L;
  public static final long CKA_UNIQUE_ID                      = 0x00000004L;
  public static final long CKA_APPLICATION                    = 0x00000010L;
  public static final long CKA_VALUE                          = 0x00000011L;
  public static final long CKA_OBJECT_ID                      = 0x00000012L;
  public static final long CKA_CERTIFICATE_TYPE               = 0x00000080L;
  public static final long CKA_ISSUER                         = 0x00000081L;
  public static final long CKA_SERIAL_NUMBER                  = 0x00000082L;
  public static final long CKA_TRUSTED                        = 0x00000086L;
  public static final long CKA_CERTIFICATE_CATEGORY           = 0x00000087L;
  public static final long CKA_JAVA_MIDP_SECURITY_DOMAIN      = 0x00000088L;
  public static final long CKA_URL                            = 0x00000089L;
  public static final long CKA_HASH_OF_SUBJECT_PUBLIC_KEY     = 0x0000008AL;
  public static final long CKA_HASH_OF_ISSUER_PUBLIC_KEY      = 0x0000008BL;
  public static final long CKA_NAME_HASH_ALGORITHM            = 0x0000008CL;
  public static final long CKA_CHECK_VALUE                    = 0x00000090L;

  public static final long CKA_KEY_TYPE                       = 0x00000100L;
  public static final long CKA_SUBJECT                        = 0x00000101L;
  public static final long CKA_ID                             = 0x00000102L;
  public static final long CKA_SENSITIVE                      = 0x00000103L;
  public static final long CKA_ENCRYPT                        = 0x00000104L;
  public static final long CKA_DECRYPT                        = 0x00000105L;
  public static final long CKA_WRAP                           = 0x00000106L;
  public static final long CKA_UNWRAP                         = 0x00000107L;
  public static final long CKA_SIGN                           = 0x00000108L;
  public static final long CKA_SIGN_RECOVER                   = 0x00000109L;
  public static final long CKA_VERIFY                         = 0x0000010AL;
  public static final long CKA_VERIFY_RECOVER                 = 0x0000010BL;
  public static final long CKA_DERIVE                         = 0x0000010CL;
  public static final long CKA_START_DATE                     = 0x00000110L;
  public static final long CKA_END_DATE                       = 0x00000111L;
  public static final long CKA_MODULUS                        = 0x00000120L;
  public static final long CKA_MODULUS_BITS                   = 0x00000121L;
  public static final long CKA_PUBLIC_EXPONENT                = 0x00000122L;
  public static final long CKA_PRIVATE_EXPONENT               = 0x00000123L;
  public static final long CKA_PRIME_1                        = 0x00000124L;
  public static final long CKA_PRIME_2                        = 0x00000125L;
  public static final long CKA_EXPONENT_1                     = 0x00000126L;
  public static final long CKA_EXPONENT_2                     = 0x00000127L;
  public static final long CKA_COEFFICIENT                    = 0x00000128L;
  public static final long CKA_PUBLIC_KEY_INFO                = 0x00000129L;
  public static final long CKA_PRIME                          = 0x00000130L;
  public static final long CKA_SUBPRIME                       = 0x00000131L;
  public static final long CKA_BASE                           = 0x00000132L;

  public static final long CKA_PRIME_BITS                     = 0x00000133L;
  public static final long CKA_SUBPRIME_BITS                  = 0x00000134L;

  public static final long CKA_VALUE_BITS                     = 0x00000160L;
  public static final long CKA_VALUE_LEN                      = 0x00000161L;
  public static final long CKA_EXTRACTABLE                    = 0x00000162L;
  public static final long CKA_LOCAL                          = 0x00000163L;
  public static final long CKA_NEVER_EXTRACTABLE              = 0x00000164L;
  public static final long CKA_ALWAYS_SENSITIVE               = 0x00000165L;
  public static final long CKA_KEY_GEN_MECHANISM              = 0x00000166L;

  public static final long CKA_MODIFIABLE                     = 0x00000170L;
  public static final long CKA_COPYABLE                       = 0x00000171L;

  public static final long CKA_DESTROYABLE                    = 0x00000172L;

  public static final long CKA_EC_PARAMS                      = 0x00000180L;

  public static final long CKA_EC_POINT                       = 0x00000181L;

  public static final long CKA_ALWAYS_AUTHENTICATE            = 0x00000202L;

  public static final long CKA_WRAP_WITH_TRUSTED              = 0x00000210L;
  public static final long CKA_WRAP_TEMPLATE
      = (CKF_ARRAY_ATTRIBUTE | 0x00000211L);
  public static final long CKA_UNWRAP_TEMPLATE
      = (CKF_ARRAY_ATTRIBUTE | 0x00000212L);
  public static final long CKA_DERIVE_TEMPLATE
      = (CKF_ARRAY_ATTRIBUTE | 0x00000213L);

  public static final long CKA_HW_FEATURE_TYPE                = 0x00000300L;

  public static final long CKA_ALLOWED_MECHANISMS
      = (CKF_ARRAY_ATTRIBUTE | 0x00000600L);
  /* new post-quantum (general) */
  public static final long CKA_PARAMETER_SET              = 0x0000061dL;
  /* KEM */
  public static final long CKA_ENCAPSULATE_TEMPLATE       = 0x0000062aL;
  public static final long CKA_DECAPSULATE_TEMPLATE       = 0x0000062bL;

  /* trust objects */
  public static final long CKA_ENCAPSULATE                = 0x00000633L;
  public static final long CKA_DECAPSULATE                = 0x00000634L;
  public static final long CKA_PUBLIC_CRC64_VALUE         = 0x00000636L;
  /* new post-quantum (general) */
  public static final long CKA_SEED                       = 0x00000637L;

  public static final long CKA_VENDOR_DEFINED                 = 0x80000000L;

  /* the following mechanism types are defined: */
  public static final long CKM_RSA_PKCS_KEY_PAIR_GEN          = 0x00000000L;
  public static final long CKM_RSA_PKCS                       = 0x00000001L;
  public static final long CKM_RSA_9796                       = 0x00000002L;
  public static final long CKM_RSA_X_509                      = 0x00000003L;

  public static final long CKM_SHA1_RSA_PKCS                  = 0x00000006L;

  public static final long CKM_RSA_PKCS_OAEP                  = 0x00000009L;

  public static final long CKM_RSA_X9_31_KEY_PAIR_GEN         = 0x0000000AL;
  public static final long CKM_RSA_X9_31                      = 0x0000000BL;
  public static final long CKM_SHA1_RSA_X9_31                 = 0x0000000CL;
  public static final long CKM_RSA_PKCS_PSS                   = 0x0000000DL;
  public static final long CKM_SHA1_RSA_PKCS_PSS              = 0x0000000EL;

  public static final long CKM_SHA256_RSA_PKCS                = 0x00000040L;
  public static final long CKM_SHA384_RSA_PKCS                = 0x00000041L;
  public static final long CKM_SHA512_RSA_PKCS                = 0x00000042L;
  public static final long CKM_SHA256_RSA_PKCS_PSS            = 0x00000043L;
  public static final long CKM_SHA384_RSA_PKCS_PSS            = 0x00000044L;
  public static final long CKM_SHA512_RSA_PKCS_PSS            = 0x00000045L;

  public static final long CKM_SHA224_RSA_PKCS                = 0x00000046L;
  public static final long CKM_SHA224_RSA_PKCS_PSS            = 0x00000047L;

  public static final long CKM_SHA512_224                     = 0x00000048L;
  public static final long CKM_SHA512_224_HMAC                = 0x00000049L;
  public static final long CKM_SHA512_224_HMAC_GENERAL        = 0x0000004AL;
  public static final long CKM_SHA512_256                     = 0x0000004CL;
  public static final long CKM_SHA512_256_HMAC                = 0x0000004DL;
  public static final long CKM_SHA512_256_HMAC_GENERAL        = 0x0000004EL;

  public static final long CKM_SHA512_T                       = 0x00000050L;
  public static final long CKM_SHA512_T_HMAC                  = 0x00000051L;
  public static final long CKM_SHA512_T_HMAC_GENERAL          = 0x00000052L;

  public static final long CKM_SHA3_256_RSA_PKCS              = 0x00000060L;
  public static final long CKM_SHA3_384_RSA_PKCS              = 0x00000061L;
  public static final long CKM_SHA3_512_RSA_PKCS              = 0x00000062L;
  public static final long CKM_SHA3_256_RSA_PKCS_PSS          = 0x00000063L;
  public static final long CKM_SHA3_384_RSA_PKCS_PSS          = 0x00000064L;
  public static final long CKM_SHA3_512_RSA_PKCS_PSS          = 0x00000065L;
  public static final long CKM_SHA3_224_RSA_PKCS              = 0x00000066L;
  public static final long CKM_SHA3_224_RSA_PKCS_PSS          = 0x00000067L;

  public static final long CKM_DES3_KEY_GEN                   = 0x00000131L;
  public static final long CKM_DES3_ECB                       = 0x00000132L;
  public static final long CKM_DES3_CBC                       = 0x00000133L;
  public static final long CKM_DES3_MAC                       = 0x00000134L;

  public static final long CKM_DES3_MAC_GENERAL               = 0x00000135L;
  public static final long CKM_DES3_CBC_PAD                   = 0x00000136L;
  public static final long CKM_DES3_CMAC_GENERAL              = 0x00000137L;
  public static final long CKM_DES3_CMAC                      = 0x00000138L;

  public static final long CKM_SHA_1                          = 0x00000220L;

  public static final long CKM_SHA_1_HMAC                     = 0x00000221L;
  public static final long CKM_SHA_1_HMAC_GENERAL             = 0x00000222L;

  public static final long CKM_SHA256                         = 0x00000250L;
  public static final long CKM_SHA256_HMAC                    = 0x00000251L;
  public static final long CKM_SHA256_HMAC_GENERAL            = 0x00000252L;
  public static final long CKM_SHA224                         = 0x00000255L;
  public static final long CKM_SHA224_HMAC                    = 0x00000256L;
  public static final long CKM_SHA224_HMAC_GENERAL            = 0x00000257L;
  public static final long CKM_SHA384                         = 0x00000260L;
  public static final long CKM_SHA384_HMAC                    = 0x00000261L;
  public static final long CKM_SHA384_HMAC_GENERAL            = 0x00000262L;
  public static final long CKM_SHA512                         = 0x00000270L;
  public static final long CKM_SHA512_HMAC                    = 0x00000271L;
  public static final long CKM_SHA512_HMAC_GENERAL            = 0x00000272L;

  public static final long CKM_SHA3_256                       = 0x000002B0L;
  public static final long CKM_SHA3_256_HMAC                  = 0x000002B1L;
  public static final long CKM_SHA3_256_HMAC_GENERAL          = 0x000002B2L;
  public static final long CKM_SHA3_256_KEY_GEN               = 0x000002B3L;
  public static final long CKM_SHA3_224                       = 0x000002B5L;
  public static final long CKM_SHA3_224_HMAC                  = 0x000002B6L;
  public static final long CKM_SHA3_224_HMAC_GENERAL          = 0x000002B7L;
  public static final long CKM_SHA3_224_KEY_GEN               = 0x000002B8L;
  public static final long CKM_SHA3_384                       = 0x000002C0L;
  public static final long CKM_SHA3_384_HMAC                  = 0x000002C1L;
  public static final long CKM_SHA3_384_HMAC_GENERAL          = 0x000002C2L;
  public static final long CKM_SHA3_384_KEY_GEN               = 0x000002C3L;
  public static final long CKM_SHA3_512                       = 0x000002D0L;
  public static final long CKM_SHA3_512_HMAC                  = 0x000002D1L;
  public static final long CKM_SHA3_512_HMAC_GENERAL          = 0x000002D2L;
  public static final long CKM_SHA3_512_KEY_GEN               = 0x000002D3L;

  public static final long CKM_GENERIC_SECRET_KEY_GEN         = 0x00000350L;

  public static final long CKM_EC_KEY_PAIR_GEN                = 0x00001040L;

  /**
   * Use CKM_EC_KEY_PAIR_GEN instead.
   */
  @Deprecated
  public static final long CKM_ECDSA_KEY_PAIR_GEN = CKM_EC_KEY_PAIR_GEN;

  public static final long CKM_ECDSA                          = 0x00001041L;
  public static final long CKM_ECDSA_SHA1                     = 0x00001042L;
  public static final long CKM_ECDSA_SHA224                   = 0x00001043L;
  public static final long CKM_ECDSA_SHA256                   = 0x00001044L;
  public static final long CKM_ECDSA_SHA384                   = 0x00001045L;
  public static final long CKM_ECDSA_SHA512                   = 0x00001046L;

  public static final long CKM_AES_XTS                        = 0x00001071L;
  public static final long CKM_AES_XTS_KEY_GEN                = 0x00001072L;
  public static final long CKM_AES_KEY_GEN                    = 0x00001080L;
  public static final long CKM_AES_MAC                        = 0x00001083L;
  public static final long CKM_AES_MAC_GENERAL                = 0x00001084L;
  public static final long CKM_AES_CBC_PAD                    = 0x00001085L;
  public static final long CKM_AES_GCM                        = 0x00001087L;
  public static final long CKM_AES_CCM                        = 0x00001088L;
  public static final long CKM_AES_CTS                        = 0x00001089L;
  public static final long CKM_AES_CMAC                       = 0x0000108AL;
  public static final long CKM_AES_CMAC_GENERAL               = 0x0000108BL;

  public static final long CKM_AES_XCBC_MAC                   = 0x0000108CL;
  public static final long CKM_AES_XCBC_MAC_96                = 0x0000108DL;
  public static final long CKM_AES_GMAC                       = 0x0000108EL;

  public static final long CKM_CHACHA20_KEY_GEN               = 0x00001225L;

  public static final long CKM_SHA_1_KEY_GEN                  = 0x00004003L;
  public static final long CKM_SHA224_KEY_GEN                 = 0x00004004L;
  public static final long CKM_SHA256_KEY_GEN                 = 0x00004005L;
  public static final long CKM_SHA384_KEY_GEN                 = 0x00004006L;
  public static final long CKM_SHA512_KEY_GEN                 = 0x00004007L;
  public static final long CKM_SHA512_224_KEY_GEN             = 0x00004008L;
  public static final long CKM_SHA512_256_KEY_GEN             = 0x00004009L;
  public static final long CKM_SHA512_T_KEY_GEN               = 0x0000400aL;
  public static final long CKM_NULL                           = 0x0000400bL;
  public static final long CKM_BLAKE2B_160                    = 0x0000400cL;
  public static final long CKM_BLAKE2B_160_HMAC               = 0x0000400dL;
  public static final long CKM_BLAKE2B_160_HMAC_GENERAL       = 0x0000400eL;
  public static final long CKM_BLAKE2B_160_KEY_DERIVE         = 0x0000400fL;
  public static final long CKM_BLAKE2B_160_KEY_GEN            = 0x00004010L;
  public static final long CKM_BLAKE2B_256                    = 0x00004011L;
  public static final long CKM_BLAKE2B_256_HMAC               = 0x00004012L;
  public static final long CKM_BLAKE2B_256_HMAC_GENERAL       = 0x00004013L;
  public static final long CKM_BLAKE2B_256_KEY_DERIVE         = 0x00004014L;
  public static final long CKM_BLAKE2B_256_KEY_GEN            = 0x00004015L;
  public static final long CKM_BLAKE2B_384                    = 0x00004016L;
  public static final long CKM_BLAKE2B_384_HMAC               = 0x00004017L;
  public static final long CKM_BLAKE2B_384_HMAC_GENERAL       = 0x00004018L;
  public static final long CKM_BLAKE2B_384_KEY_DERIVE         = 0x00004019L;
  public static final long CKM_BLAKE2B_384_KEY_GEN            = 0x0000401aL;
  public static final long CKM_BLAKE2B_512                    = 0x0000401bL;
  public static final long CKM_BLAKE2B_512_HMAC               = 0x0000401cL;
  public static final long CKM_BLAKE2B_512_HMAC_GENERAL       = 0x0000401dL;
  public static final long CKM_BLAKE2B_512_KEY_DERIVE         = 0x0000401eL;
  public static final long CKM_BLAKE2B_512_KEY_GEN            = 0x0000401fL;
  public static final long CKM_SALSA20                        = 0x00004020L;
  public static final long CKM_CHACHA20_POLY1305              = 0x00004021L;
  public static final long CKM_SALSA20_POLY1305               = 0x00004022L;
  public static final long CKM_XEDDSA                         = 0x00004029L;
  public static final long CKM_HKDF_DERIVE                    = 0x0000402aL;
  public static final long CKM_HKDF_DATA                      = 0x0000402bL;
  public static final long CKM_HKDF_KEY_GEN                   = 0x0000402cL;
  public static final long CKM_ECDSA_SHA3_224                 = 0x00001047L;
  public static final long CKM_ECDSA_SHA3_256                 = 0x00001048L;
  public static final long CKM_ECDSA_SHA3_384                 = 0x00001049L;
  public static final long CKM_ECDSA_SHA3_512                 = 0x0000104aL;
  public static final long CKM_EC_EDWARDS_KEY_PAIR_GEN        = 0x00001055L;
  public static final long CKM_EC_MONTGOMERY_KEY_PAIR_GEN     = 0x00001056L;
  public static final long CKM_EDDSA                          = 0x00001057L;

  public static final long CKM_HSS_KEY_PAIR_GEN          = 0x00004032L;
  public static final long CKM_HSS                       = 0x00004033L;

  public static final long CKM_XMSS_KEY_PAIR_GEN         = 0x00004034L;
  public static final long CKM_XMSSMT_KEY_PAIR_GEN       = 0x00004035L;
  public static final long CKM_XMSS                      = 0x00004036L;
  public static final long CKM_XMSSMT                    = 0x00004037L;

  public static final long CKM_ML_KEM_KEY_PAIR_GEN       = 0x0000000fL;
  public static final long CKM_ML_KEM                    = 0x00000017L;

  public static final long CKM_ML_DSA_KEY_PAIR_GEN       = 0x0000001cL;
  public static final long CKM_ML_DSA                    = 0x0000001dL;
  public static final long CKM_HASH_ML_DSA               = 0x0000001fL;
  public static final long CKM_HASH_ML_DSA_SHA224        = 0x00000023L;
  public static final long CKM_HASH_ML_DSA_SHA256        = 0x00000024L;
  public static final long CKM_HASH_ML_DSA_SHA384        = 0x00000025L;
  public static final long CKM_HASH_ML_DSA_SHA512        = 0x00000026L;
  public static final long CKM_HASH_ML_DSA_SHA3_224      = 0x00000027L;
  public static final long CKM_HASH_ML_DSA_SHA3_256      = 0x00000028L;
  public static final long CKM_HASH_ML_DSA_SHA3_384      = 0x00000029L;
  public static final long CKM_HASH_ML_DSA_SHA3_512      = 0x0000002aL;
  public static final long CKM_HASH_ML_DSA_SHAKE128      = 0x0000002bL;
  public static final long CKM_HASH_ML_DSA_SHAKE256      = 0x0000002cL;

  public static final long CKM_SLH_DSA_KEY_PAIR_GEN      = 0x0000002dL;
  public static final long CKM_SLH_DSA                   = 0x0000002eL;
  public static final long CKM_HASH_SLH_DSA              = 0x00000034L;
  public static final long CKM_HASH_SLH_DSA_SHA224       = 0x00000036L;
  public static final long CKM_HASH_SLH_DSA_SHA256       = 0x00000037L;
  public static final long CKM_HASH_SLH_DSA_SHA384       = 0x00000038L;
  public static final long CKM_HASH_SLH_DSA_SHA512       = 0x00000039L;
  public static final long CKM_HASH_SLH_DSA_SHA3_224     = 0x0000003aL;
  public static final long CKM_HASH_SLH_DSA_SHA3_256     = 0x0000003bL;
  public static final long CKM_HASH_SLH_DSA_SHA3_384     = 0x0000003cL;
  public static final long CKM_HASH_SLH_DSA_SHA3_512     = 0x0000003dL;
  public static final long CKM_HASH_SLH_DSA_SHAKE128     = 0x0000003eL;
  public static final long CKM_HASH_SLH_DSA_SHAKE256     = 0x0000003fL;

  public static final long CKM_VENDOR_DEFINED                 = 0x80000000L;

  /* The flags are defined as follows:
   *      Bit Flag               Mask          Meaning */
  public static final long CKF_HW                             = 0x00000001L;

  /* Specify whether a mechanism can be used for a particular task */
  public static final long CKF_FIND_OBJECTS                   = 0x00000040L;

  public static final long CKF_ENCRYPT                        = 0x00000100L;
  public static final long CKF_DECRYPT                        = 0x00000200L;
  public static final long CKF_DIGEST                         = 0x00000400L;
  public static final long CKF_SIGN                           = 0x00000800L;
  public static final long CKF_SIGN_RECOVER                   = 0x00001000L;
  public static final long CKF_VERIFY                         = 0x00002000L;
  public static final long CKF_VERIFY_RECOVER                 = 0x00004000L;
  public static final long CKF_GENERATE                       = 0x00008000L;
  public static final long CKF_GENERATE_KEY_PAIR              = 0x00010000L;
  public static final long CKF_WRAP                           = 0x00020000L;
  public static final long CKF_UNWRAP                         = 0x00040000L;
  public static final long CKF_DERIVE                         = 0x00080000L;

  /* Describe a token's EC capabilities not available in mechanism
   * information.
   */
  public static final long CKF_EC_F_P                         = 0x00100000L;
  public static final long CKF_EC_F_2M                        = 0x00200000L;
  public static final long CKF_EC_ECPARAMETERS                = 0x00400000L;
  public static final long CKF_EC_OID                         = 0x00800000L;
  /**
   * Use CKF_EC_OID instead.
   */
  @Deprecated
  public static final long CKF_EC_NAMEDCURVE                  = CKF_EC_OID;
  public static final long CKF_EC_UNCOMPRESS                  = 0x01000000L;
  public static final long CKF_EC_COMPRESS                    = 0x02000000L;
  public static final long CKF_EC_CURVENAME                   = 0x04000000L;

  public static final long CKF_ENCAPSULATE       = 0x10000000L;
  public static final long CKF_DECAPSULATE       = 0x20000000L;

  public static final long CKR_OK                             = 0x00000000L;
  public static final long CKR_CANCEL                         = 0x00000001L;
  public static final long CKR_HOST_MEMORY                    = 0x00000002L;
  public static final long CKR_SLOT_ID_INVALID                = 0x00000003L;

  public static final long CKR_GENERAL_ERROR                  = 0x00000005L;
  public static final long CKR_FUNCTION_FAILED                = 0x00000006L;

  public static final long CKR_ARGUMENTS_BAD                  = 0x00000007L;
  public static final long CKR_NO_EVENT                       = 0x00000008L;
  public static final long CKR_NEED_TO_CREATE_THREADS         = 0x00000009L;
  public static final long CKR_CANT_LOCK                      = 0x0000000AL;

  public static final long CKR_ATTRIBUTE_READ_ONLY            = 0x00000010L;
  public static final long CKR_ATTRIBUTE_SENSITIVE            = 0x00000011L;
  public static final long CKR_ATTRIBUTE_TYPE_INVALID         = 0x00000012L;
  public static final long CKR_ATTRIBUTE_VALUE_INVALID        = 0x00000013L;

  public static final long CKR_ACTION_PROHIBITED              = 0x0000001BL;

  public static final long CKR_DATA_INVALID                   = 0x00000020L;
  public static final long CKR_DATA_LEN_RANGE                 = 0x00000021L;
  public static final long CKR_DEVICE_ERROR                   = 0x00000030L;
  public static final long CKR_DEVICE_MEMORY                  = 0x00000031L;
  public static final long CKR_DEVICE_REMOVED                 = 0x00000032L;
  public static final long CKR_ENCRYPTED_DATA_INVALID         = 0x00000040L;
  public static final long CKR_ENCRYPTED_DATA_LEN_RANGE       = 0x00000041L;
  public static final long CKR_AEAD_DECRYPT_FAILED            = 0x00000042L;
  public static final long CKR_FUNCTION_CANCELED              = 0x00000050L;
  public static final long CKR_FUNCTION_NOT_PARALLEL          = 0x00000051L;

  public static final long CKR_FUNCTION_NOT_SUPPORTED         = 0x00000054L;

  public static final long CKR_KEY_HANDLE_INVALID             = 0x00000060L;

  public static final long CKR_KEY_SIZE_RANGE                 = 0x00000062L;
  public static final long CKR_KEY_TYPE_INCONSISTENT          = 0x00000063L;

  public static final long CKR_KEY_NOT_NEEDED                 = 0x00000064L;
  public static final long CKR_KEY_CHANGED                    = 0x00000065L;
  public static final long CKR_KEY_NEEDED                     = 0x00000066L;
  public static final long CKR_KEY_INDIGESTIBLE               = 0x00000067L;
  public static final long CKR_KEY_FUNCTION_NOT_PERMITTED     = 0x00000068L;
  public static final long CKR_KEY_NOT_WRAPPABLE              = 0x00000069L;
  public static final long CKR_KEY_UNEXTRACTABLE              = 0x0000006AL;

  public static final long CKR_MECHANISM_INVALID              = 0x00000070L;
  public static final long CKR_MECHANISM_PARAM_INVALID        = 0x00000071L;

  public static final long CKR_OBJECT_HANDLE_INVALID          = 0x00000082L;
  public static final long CKR_OPERATION_ACTIVE               = 0x00000090L;
  public static final long CKR_OPERATION_NOT_INITIALIZED      = 0x00000091L;
  public static final long CKR_PIN_INCORRECT                  = 0x000000A0L;
  public static final long CKR_PIN_INVALID                    = 0x000000A1L;
  public static final long CKR_PIN_LEN_RANGE                  = 0x000000A2L;

  public static final long CKR_PIN_EXPIRED                    = 0x000000A3L;
  public static final long CKR_PIN_LOCKED                     = 0x000000A4L;

  public static final long CKR_SESSION_CLOSED                 = 0x000000B0L;
  public static final long CKR_SESSION_COUNT                  = 0x000000B1L;
  public static final long CKR_SESSION_HANDLE_INVALID         = 0x000000B3L;
  public static final long CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4L;
  public static final long CKR_SESSION_READ_ONLY              = 0x000000B5L;
  public static final long CKR_SESSION_EXISTS                 = 0x000000B6L;

  public static final long CKR_SESSION_READ_ONLY_EXISTS       = 0x000000B7L;
  public static final long CKR_SESSION_READ_WRITE_SO_EXISTS   = 0x000000B8L;

  public static final long CKR_SIGNATURE_INVALID              = 0x000000C0L;
  public static final long CKR_SIGNATURE_LEN_RANGE            = 0x000000C1L;
  public static final long CKR_TEMPLATE_INCOMPLETE            = 0x000000D0L;
  public static final long CKR_TEMPLATE_INCONSISTENT          = 0x000000D1L;
  public static final long CKR_TOKEN_NOT_PRESENT              = 0x000000E0L;
  public static final long CKR_TOKEN_NOT_RECOGNIZED           = 0x000000E1L;
  public static final long CKR_TOKEN_WRITE_PROTECTED          = 0x000000E2L;
  public static final long CKR_UNWRAPPING_KEY_HANDLE_INVALID  = 0x000000F0L;
  public static final long CKR_UNWRAPPING_KEY_SIZE_RANGE      = 0x000000F1L;
  public static final long CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2L;
  public static final long CKR_USER_ALREADY_LOGGED_IN         = 0x00000100L;
  public static final long CKR_USER_NOT_LOGGED_IN             = 0x00000101L;
  public static final long CKR_USER_PIN_NOT_INITIALIZED       = 0x00000102L;
  public static final long CKR_USER_TYPE_INVALID              = 0x00000103L;

  public static final long CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104L;
  public static final long CKR_USER_TOO_MANY_TYPES            = 0x00000105L;

  public static final long CKR_WRAPPED_KEY_INVALID            = 0x00000110L;
  public static final long CKR_WRAPPED_KEY_LEN_RANGE          = 0x00000112L;
  public static final long CKR_WRAPPING_KEY_HANDLE_INVALID    = 0x00000113L;
  public static final long CKR_WRAPPING_KEY_SIZE_RANGE        = 0x00000114L;
  public static final long CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115L;
  public static final long CKR_RANDOM_SEED_NOT_SUPPORTED      = 0x00000120L;

  public static final long CKR_RANDOM_NO_RNG                  = 0x00000121L;

  public static final long CKR_DOMAIN_PARAMS_INVALID          = 0x00000130L;

  public static final long CKR_CURVE_NOT_SUPPORTED            = 0x00000140L;

  public static final long CKR_BUFFER_TOO_SMALL               = 0x00000150L;
  public static final long CKR_SAVED_STATE_INVALID            = 0x00000160L;
  public static final long CKR_INFORMATION_SENSITIVE          = 0x00000170L;
  public static final long CKR_STATE_UNSAVEABLE               = 0x00000180L;

  public static final long CKR_CRYPTOKI_NOT_INITIALIZED       = 0x00000190L;
  public static final long CKR_CRYPTOKI_ALREADY_INITIALIZED   = 0x00000191L;
  public static final long CKR_MUTEX_BAD                      = 0x000001A0L;
  public static final long CKR_MUTEX_NOT_LOCKED               = 0x000001A1L;

  public static final long CKR_NEW_PIN_MODE                   = 0x000001B0L;
  public static final long CKR_NEXT_OTP                       = 0x000001B1L;

  public static final long CKR_EXCEEDED_MAX_ITERATIONS        = 0x000001B5L;
  public static final long CKR_FIPS_SELF_TEST_FAILED          = 0x000001B6L;
  public static final long CKR_LIBRARY_LOAD_FAILED            = 0x000001B7L;
  public static final long CKR_PIN_TOO_WEAK                   = 0x000001B8L;
  public static final long CKR_PUBLIC_KEY_INVALID             = 0x000001B9L;

  public static final long CKR_FUNCTION_REJECTED              = 0x00000200L;
  public static final long CKR_TOKEN_RESOURCE_EXCEEDED        = 0x00000201L;

  public static final long CKR_OPERATION_CANCEL_FAILED          = 0x00000202L;
  public static final long CKR_KEY_EXHAUSTED                    = 0x00000203L;

  public static final long CKR_PENDING                          = 0x00000204L;
  public static final long CKR_SESSION_ASYNC_NOT_SUPPORTED      = 0x00000205L;
  public static final long CKR_SEED_RANDOM_REQUIRED             = 0x00000206L;
  public static final long CKR_OPERATION_NOT_VALIDATED          = 0x00000207L;
  public static final long CKR_TOKEN_NOT_INITIALIZED            = 0x00000208L;
  public static final long CKR_PARAMETER_SET_NOT_SUPPORTED      = 0x00000209L;

  public static final long CKR_VENDOR_DEFINED                 = 0x80000000L;

  public static final long CKF_END_OF_MESSAGE                 = 0x00000001L;

  /* Get functionlist flags */
  public static final long CKF_INTERFACE_FORK_SAFE            = 0x00000001L;

  /* flags: bit flags that provide capabilities of the slot
   *      Bit Flag                           Mask       Meaning
   */
  public static final long CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001L;
  public static final long CKF_OS_LOCKING_OK                  = 0x00000002L;

  /* additional flags for parameters to functions */

  /* The following MGFs are defined */
  public static final long CKG_MGF1_SHA1                      = 0x00000001L;
  public static final long CKG_MGF1_SHA256                    = 0x00000002L;
  public static final long CKG_MGF1_SHA384                    = 0x00000003L;
  public static final long CKG_MGF1_SHA512                    = 0x00000004L;
  public static final long CKG_MGF1_SHA224                    = 0x00000005L;
  public static final long CKG_MGF1_SHA3_224                  = 0x00000006L;
  public static final long CKG_MGF1_SHA3_256                  = 0x00000007L;
  public static final long CKG_MGF1_SHA3_384                  = 0x00000008L;
  public static final long CKG_MGF1_SHA3_512                  = 0x00000009L;

  /*
   * New PKCS 11 v3.0 data structures.
   */

  /* Typedefs for Flexible KDF */
  public static final long CK_SP800_108_ITERATION_VARIABLE    = 0x00000001L;
  public static final long CK_SP800_108_OPTIONAL_COUNTER      = 0x00000002L;
  public static final long CK_SP800_108_DKM_LENGTH            = 0x00000003L;
  public static final long CK_SP800_108_BYTE_ARRAY            = 0x00000004L;

  private static final long THIS_VENDOR                       = 0xFFFFF000L;

  // CKK
  // SM Series
  public static final long CKK_VENDOR_SM2              = THIS_VENDOR | 0x0001L;
  public static final long CKK_VENDOR_SM4              = THIS_VENDOR | 0x0002L;

  // CKM
  // SM Series
  public static final long CKM_VENDOR_SM2_KEY_PAIR_GEN = THIS_VENDOR | 0x0001L;
  public static final long CKM_VENDOR_SM2              = THIS_VENDOR | 0x0002L;
  public static final long CKM_VENDOR_SM2_SM3          = THIS_VENDOR | 0x0003L;
  public static final long CKM_VENDOR_SM2_ENCRYPT      = THIS_VENDOR | 0x0004L;
  public static final long CKM_VENDOR_SM3              = THIS_VENDOR | 0x0005L;
  public static final long CKM_VENDOR_SM4_KEY_GEN      = THIS_VENDOR | 0x0006L;
  public static final long CKM_VENDOR_SM4_ECB          = THIS_VENDOR | 0x0007L;
  public static final long CKM_VENDOR_SM4_CBC          = THIS_VENDOR | 0x0008L;
  public static final long CKM_VENDOR_SM4_MAC_GENERAL  = THIS_VENDOR | 0x0009L;
  public static final long CKM_VENDOR_SM4_MAC          = THIS_VENDOR | 0x000AL;
  public static final long CKM_VENDOR_SM4_CBC_PAD      = THIS_VENDOR | 0x000BL;
  public static final long CKM_VENDOR_SM4_CCM          = THIS_VENDOR | 0x000CL;
  public static final long CKM_VENDOR_SM4_GCM          = THIS_VENDOR | 0x000DL;

  /* ML-DSA values for CKA_PARAMETER_SETS */
  public static final long CKP_ML_DSA_44         = 0x00000001L;
  public static final long CKP_ML_DSA_65         = 0x00000002L;
  public static final long CKP_ML_DSA_87         = 0x00000003L;

  /* SLH-DSA values for CKA_PARAMETER_SETS */
  public static final long CKP_SLH_DSA_SHA2_128S   = 0x00000001L;
  public static final long CKP_SLH_DSA_SHAKE_128S  = 0x00000002L;
  public static final long CKP_SLH_DSA_SHA2_128F   = 0x00000003L;
  public static final long CKP_SLH_DSA_SHAKE_128F  = 0x00000004L;
  public static final long CKP_SLH_DSA_SHA2_192S   = 0x00000005L;
  public static final long CKP_SLH_DSA_SHAKE_192S  = 0x00000006L;
  public static final long CKP_SLH_DSA_SHA2_192F   = 0x00000007L;
  public static final long CKP_SLH_DSA_SHAKE_192F  = 0x00000008L;
  public static final long CKP_SLH_DSA_SHA2_256S   = 0x00000009L;
  public static final long CKP_SLH_DSA_SHAKE_256S  = 0x0000000aL;
  public static final long CKP_SLH_DSA_SHA2_256F   = 0x0000000bL;
  public static final long CKP_SLH_DSA_SHAKE_256F  = 0x0000000cL;

  /* ML-KEM values for CKA_PARAMETER_SETS */
  public static final long CKP_ML_KEM_512        = 0x00000001L;
  public static final long CKP_ML_KEM_768        = 0x00000002L;
  public static final long CKP_ML_KEM_1024       = 0x00000003L;

  /* generic PQ mechanism parameters */
  public static final long CKH_HEDGE_PREFERRED        = 0x00000000L;
  public static final long CKH_HEDGE_REQUIRED         = 0x00000001L;
  public static final long CKH_DETERMINISTIC_REQUIRED = 0x00000002L;

  private PKCS11T() {
  }

  public static boolean isUnavailableInformation(long value) {
    return value == CK_UNAVAILABLE_INFORMATION;
  }

  private static class CodeNameMap {

    private final Category category;

    private final Map<Long, String> codeNameMap;
    private final Map<String, Long> nameCodeMap;

    CodeNameMap(Category category, JsonMap nameCodeTextMap) {
      this.category = category;

      codeNameMap = new HashMap<>();
      nameCodeMap = new HashMap<>();

      try {
        for (String name : nameCodeTextMap.getKeys()) {
          String codeText = nameCodeTextMap.getNnString(name);
          Long code = Functions.parseLong(codeText);
          if (code == null) {
            throw new IllegalStateException("invalid code '" + codeText + "'");
          }

          String upperName = name.toUpperCase(Locale.ROOT);
          if (codeNameMap.containsKey(code)) {
            nameCodeMap.put(upperName, code);
          } else {
            codeNameMap.put(code, upperName);
          }
        }

        Set<Long> codes = codeNameMap.keySet();
        for (Long code : codes) {
          nameCodeMap.put(codeNameMap.get(code), code);
        }
      } catch (Throwable t) {
        throw new IllegalStateException("error reading configuration for " +
            category, t);
      }

      if (codeNameMap.isEmpty()) {
        throw new IllegalStateException("no code to name map is defined for " +
            category);
      }
    }

    String codeToString(long code) {
      String name = codeNameMap.get(code);
      return name != null ? name : category.getPrefix() + "_0X"
          + Functions.toFullHexUpper(code);
    }

    Long stringToCode(String name) {
      return nameCodeMap.get(name);
    }

    Set<Long> codes() {
      return codeNameMap.keySet();
    }

  }

  /**
   * Converts the long value code to a name.
   *
   * @param category The category of code.
   * @param code The code to be converted to a string.
   * @return The string representation of the given code.
   */
  public static String codeToName(Category category, long code) {
    CodeNameMap map = codeNameMaps.get(category);
    if (map == null) {
      throw new IllegalArgumentException("Unknown category " + category);
    }
    return map.codeToString(code);
  }

  /**
   * Converts the name to code value.
   *
   * @param category The category of code.
   * @param name The name to be converted to a code.
   * @return The code representation of the given name.
   */
  public static Long nameToCode(Category category, String name) {
    Long code = Functions.parseLong(name);
    if (code != null) {
      return code;
    }

    CodeNameMap map = codeNameMaps.get(category);
    if (map == null) {
      throw new IllegalArgumentException("Unknown category " + category);
    }
    return map.stringToCode(name.toUpperCase(Locale.ROOT));
  }

  public static String ckaCodeToName(long code) {
    return codeToName(Category.CKA, code);
  }

  public static Long ckaNameToCode(String name) {
    return nameToCode(Category.CKA, name);
  }

  public static String ckkCodeToName(long code) {
    return codeToName(Category.CKK, code);
  }

  public static Long ckkNameToCode(String name) {
    return nameToCode(Category.CKK, name);
  }

  public static String ckmCodeToName(long code) {
    return codeToName(Category.CKM, code);
  }

  public static Long ckmNameToCode(String name) {
    return nameToCode(Category.CKM, name);
  }

  public static String ckoCodeToName(long code) {
    return codeToName(Category.CKO, code);
  }

  public static Long ckoNameToCode(String name) {
    return nameToCode(Category.CKO, name);
  }

  public static String ckrCodeToName(long code) {
    return codeToName(Category.CKR, code);
  }

  public static Long ckrNameToCode(String name) {
    return nameToCode(Category.CKR, name);
  }

  public static String ckuCodeToName(long code) {
    return codeToName(Category.CKU, code);
  }

  public static Long ckuNameToCode(String name) {
    return nameToCode(Category.CKU, name);
  }

  public static String getStdMldsaName(long mldsaVariant) {
    return (mldsaVariant == CKP_ML_DSA_44) ? "ML-DSA-44"
        :  (mldsaVariant == CKP_ML_DSA_65) ? "ML-DSA-65"
        :  (mldsaVariant == CKP_ML_DSA_87) ? "ML-DSA-87"
        :  null;
  }

  public static String getStdMlkemName(long mlkemVariant) {
    return (mlkemVariant == CKP_ML_KEM_512)  ? "ML-KEM-512"
        :  (mlkemVariant == CKP_ML_KEM_768)  ? "ML-KEM-768"
        :  (mlkemVariant == CKP_ML_KEM_1024) ? "ML-KEM-1024"
        :  null;
  }

  private static final Map<Category, CodeNameMap> codeNameMaps =
      new HashMap<>(20);

  private static final Map<Long, String> hashMechCodeToHashNames;

  public static String getHashAlgName(long hashMechanism) {
    return hashMechCodeToHashNames.get(hashMechanism);
  }

  static {
    hashMechCodeToHashNames = new HashMap<>();
    hashMechCodeToHashNames.put(CKM_SHA_1, "SHA1");
    hashMechCodeToHashNames.put(CKM_SHA224, "SHA224");
    hashMechCodeToHashNames.put(CKM_SHA256, "SHA256");
    hashMechCodeToHashNames.put(CKM_SHA384, "SHA384");
    hashMechCodeToHashNames.put(CKM_SHA512, "SHA512");
    hashMechCodeToHashNames.put(CKM_SHA512_224, "SHA512/224");
    hashMechCodeToHashNames.put(CKM_SHA512_256, "SHA512/256");
    hashMechCodeToHashNames.put(CKM_SHA3_224, "SHA3-224");
    hashMechCodeToHashNames.put(CKM_SHA3_256, "SHA3-256");
    hashMechCodeToHashNames.put(CKM_SHA3_384, "SHA3-384");
    hashMechCodeToHashNames.put(CKM_SHA3_512, "SHA3-512");

    String path = "org/xipki/pkcs11/wrapper/name-code.json";
    try (InputStream is = PKCS11T.class.getClassLoader()
        .getResourceAsStream(path)) {
      JsonMap json = JsonParser.parseMap(is, true);
      for (Category m : Category.values()) {
        JsonMap map = json.getMap(m.name().toUpperCase());
        codeNameMaps.put(m, new CodeNameMap(m, map));
      }
    } catch (Exception e) {
      throw new RuntimeException("error parsing " + path, e);
    }
  }

}
