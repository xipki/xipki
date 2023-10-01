// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.ctlog;

import org.xipki.util.Base64;

/**
 * The CT Log servlet RSA.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogServletRSA extends CtLogServlet {

  private static final String privateKey =
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCNHv1OLJCMm+N19hVHykDhzuoX"
      + "9V59jCLctkgkdIPOZ59dqosKMRQCROz8Zv8LAPV1HrZgopHCTVkQgcnozifw7Hwo9JASWfPujN0S"
      + "tUvzdRUwwrWj+MqYiIfU65jxZgPbJgBV6ZoEt9twvih/uG8mLSXcGTMpedROjoDytxU8ebQaJppJ"
      + "X3JQY5pl8CWC2cT/W2J8H3O7sQzps3JreI7LE0pJY9qj6/7A0+ZQiWPKhyFAON0EHndyWK3Q0Tvr"
      + "5dgtH3Bwi9E3og/ZoP2Y6BoUJ+Zxi5Pd7qvmwmo+gtw8JNYNNyJFVb0PRUWpOkV0pUrnzHvgBsOF"
      + "pyWTtFbJX2+FAgMBAAECggEABi6gXCdZob9GhKlmH0H9+6Zr3ObT394evNqDaI1uJMGnWpwZATZL"
      + "MRpB44DDlYDSP/I7fRpCFmf7Cd0VskwttcE2YzjrgtJL/FxRZvtoO18asYsmF+vTPEFm6e30Qkb8"
      + "zkHo69qS87f2NgcukQHMZLi/mtfDxQJgSZy2i2t307FUdIR5RWU9CKkc6jhCw1v3kuCLiYYvcGXl"
      + "2Fj9dC8W8z9e4qiI2ezVA+19QdJkcdTZf8X3/XEBF8lwiJWIMZ0Du2u0AH3tu4reKP3nUYRmHxc1"
      + "kLMoWUaAiOWXIr7Av90XoDiiEJtZ4OxwZKdfHWhPcw7w+rP/9Esys1QPjFUTwQKBgQDSQhyMR+Gh"
      + "gAzivZr6RAmYY8mW3eVzYb+SUacg1CeClSvrQO+/v4t9LLWkmq5I9cmlRjoZ50lquggFVQlknaKQ"
      + "+V/hUFMGQvfCdptxGkZO0MP3ZOo8HC1Tg09l6ymDbrxMdy2hxCl3f/wRby1TErsWb6io5wnD5ggU"
      + "7y61aYMpdQKBgQCr0m2VpC1CVUZCX2DDIa3wnKEBjuocTEVGUeNRwP+gMtfu8mRG5l3s9S04aMHY"
      + "vOf823VJc5e+cxLWIpt0lZQIeoIslA6B4rBkZ5BEDZfAEtqOqtaSTSMt0eqtRKVzrQ39HoePMiIn"
      + "Cjg74wtF88FKMXwB6Axdq0npGDGOb5Zb0QKBgDL6mJVisFBKDdXEBxl6+aCbQTt1Hbb2Ek7VwWHy"
      + "TooYxQdLPVYOiTGWb4wzfOJvxa5u8pNpQqG/7UXtslNU7R+ddyPYJ+kyv4PE4jdwGW/uqjUHoMtm"
      + "QY8oHU4m0G/vn3QiyUuZljxFKcbIYALuXbI47HnXWsTGt1rsCzUtGgIpAoGAYHxgMUHqcG92btsk"
      + "eS82gAFUoI1ihdWGqUBeyI/6fDlQ7MuM6AuA/wmHBUA+arlaBLIwILkao0X3c+wnI8bDRCeXZfUW"
      + "WHW13AwUBUMkziVIOglRSQKsGJTilb4Qsu6hBlzYft8GMqoYffi3YebJyiITovZty0Pe01hUq8mZ"
      + "w6ECgYB+wvaG4v6KwCJd+4pLA5MgPHFlUIOAqPMy233Hw5+7BL+yW9QNWWqsbo5lJVhbPtN8bRo/"
      + "KnYRN3Sfe297RKtiTGRq9Nlz+t/oZqBk88vd/pkVO1HmOBf0DLmXISzkVR5j9L56h5lTN2tZYOBQ"
      + "2XNbb90PLfcDvXUpc/uwtQ2/ng==";

  private static final String publicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjR79TiyQjJvjdfYVR8pA4c7qF/VefYwi"
      + "3LZIJHSDzmefXaqLCjEUAkTs/Gb/CwD1dR62YKKRwk1ZEIHJ6M4n8Ox8KPSQElnz7ozdErVL83UV"
      + "MMK1o/jKmIiH1OuY8WYD2yYAVemaBLfbcL4of7hvJi0l3BkzKXnUTo6A8rcVPHm0GiaaSV9yUGOa"
      + "ZfAlgtnE/1tifB9zu7EM6bNya3iOyxNKSWPao+v+wNPmUIljyochQDjdBB53clit0NE76+XYLR9w"
      + "cIvRN6IP2aD9mOgaFCfmcYuT3e6r5sJqPoLcPCTWDTciRVW9D0VFqTpFdKVK58x74AbDhaclk7RW"
      + "yV9vhQIDAQAB";

  public CtLogServletRSA() {
    super(Base64.decode(privateKey), Base64.decode(publicKey));
  }

}
