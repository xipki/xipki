package org.xipki.ca.gateway.acme;

import org.xipki.util.Base64Url;

public class DummyMain {

  public static void main(String[] args) {
    try {
      String b64 = "eyJhbGciOiAiUlMyNTYiLCAiandrIjogeyJuIjogIngydmZMY1FPalZxNTNqSGVFZnJ1X05STmtFNFNUX0R1TjI5aGpVcng2ZktITnBBa0RpeldrRWVGQ1Y3aHRGZlF4aHVWeDJlU2dOaEhrMFJzZnozVXNIVEtILUhBTEw3TnZEeUl2aWlMS0tYZF9DMWhfYWJKQzBNbWV1WERUbHZ3NjFMUkVWWWM5SU54ZVp1MXo5ZWlyeG5TbEZvS21xRHNKeml3LVpBdlJMYkpxY3NraEhxSXNUbXpxZGxNNm1CWE9lOGd5cjRZbDljNjJ3SXdMdlJLaGk1bzFpYW9fLVJGeVdiVjE4Y2RTNnBBa0hOSzJERGdoT3FCQXJ4clZVWTFMSjJkb1VVT0g2MlFhdHZhc3BOSUxPLXJxbHJYMVpWZmR5RHJNYzhUMk1OOUJEOFJvNmtUUlBMODlndXpxa0NreWFCQnNmY19PVUVUWWlTSmJTY0xCUSIsICJlIjogIkFRQUIiLCAia3R5IjogIlJTQSJ9LCAibm9uY2UiOiAiRnVhY2N2RFVyNm8xaXJLTmpqbE5aUSIsICJ1cmwiOiAiaHR0cDovL2xvY2FsaG9zdDo4MDgyL2FjbWUvbmV3LWFjY291bnQifQ";
      System.out.println(new String(Base64Url.decodeFast(b64)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
