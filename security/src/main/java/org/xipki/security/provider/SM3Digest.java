// #THIRDPARTY copyright BouncyCastle, License MIT-style.

package org.xipki.security.provider;

import org.bouncycastle.util.Pack;

import java.util.Arrays;

/**
 * Implementation of Chinese SM3 digest as described at
 * https://tools.ietf.org/html/draft-shen-sm3-hash-01
 * and at .... ( Chinese PDF )
 * <p>
 * The specification says "process a bit stream",
 * but this is written to process bytes in blocks of 4,
 * meaning this will process 32-bit word groups.
 * But so do also most other digest specifications,
 * including the SHA-256 which was a origin for
 * this specification.
 */
public class SM3Digest {

  private static final int DIGEST_LENGTH = 32;   // bytes
  private static final int BLOCK_SIZE = 64 / 4; // of 32 bit ints (16 ints)

  private final byte[] xBuf = new byte[4];
  private int xBufOff;
  private long byteCount;

  private final int[] V = new int[DIGEST_LENGTH / 4]; // in 32 bit ints (8 ints)
  private final int[] inwords = new int[BLOCK_SIZE];
  private int xOff;

  // Work-bufs used within processBlock()
  private final int[] W = new int[68];

  // Round constant T for processBlock() which is 32 bit integer rolled left
  // up to (63 MOD 32) bit positions.
  private static final int[] T = new int[64];

  static {
    for (int i = 0; i < 16; ++i) {
      int t = 0x79CC4519;
      T[i] = (t << i) | (t >>> (32 - i));
    }

    for (int i = 16; i < 64; ++i) {
      int n = i % 32;
      int t = 0x7A879D8A;
      T[i] = (t << n) | (t >>> (32 - n));
    }
  }

  /**
   * Standard constructor
   */
  public SM3Digest() {
    reset();
  }

  public String getAlgorithmName() {
    return "SM3";
  }

  public int getDigestSize() {
    return DIGEST_LENGTH;
  }

  /**
   * reset the chaining variables
   */
  public void reset() {
    byteCount = 0;
    xBufOff = 0;
    Arrays.fill(xBuf, (byte) 0);

    this.V[0] = 0x7380166F;
    this.V[1] = 0x4914B2B9;
    this.V[2] = 0x172442D7;
    this.V[3] = 0xDA8A0600;
    this.V[4] = 0xA96F30BC;
    this.V[5] = 0x163138AA;
    this.V[6] = 0xE38DEE4D;
    this.V[7] = 0xB0FB0E4E;

    this.xOff = 0;
  }

  public void update(byte in) {
    xBuf[xBufOff++] = in;
    if (xBufOff == xBuf.length) {
      processWord(xBuf, 0);
      xBufOff = 0;
    }

    byteCount++;
  }

  public void update(byte[] in, int inOff, int len) {
    len = Math.max(0,  len);

    // fill the current word
    int i = 0;
    if (xBufOff != 0) {
      while (i < len) {
        xBuf[xBufOff++] = in[inOff + i++];
        if (xBufOff == 4) {
          processWord(xBuf, 0);
          xBufOff = 0;
          break;
        }
      }
    }

    // process whole words.
    int limit = len - 3;
    for (; i < limit; i += 4) {
      processWord(in, inOff + i);
    }

    // load in the remainder.
    while (i < len) {
      xBuf[xBufOff++] = in[inOff + i++];
    }

    byteCount += len;
  }

  public void finish() {
    long bitLength = (byteCount << 3);
    // add the pad bytes.
    update((byte)128);

    while (xBufOff != 0) {
      update((byte)0);
    }

    processLength(bitLength);
    processBlock();
  }

  public int doFinal(byte[] out, int outOff) {
    finish();
    Pack.intToBigEndian(V, out, outOff);
    reset();
    return DIGEST_LENGTH;
  }

  private void processWord(byte[] in, int inOff) {
    inwords[xOff++] = Pack.bigEndianToInt(in, inOff);
    if (this.xOff >= 16) {
      processBlock();
    }
  }

  private void processLength(long bitLength) {
    if (this.xOff > (BLOCK_SIZE - 2)) {
      // xOff == 15  --> can't fit the 64 bit length field at tail..
      this.inwords[this.xOff] = 0; // fill with zero
      ++this.xOff;

      processBlock();
    }

    // Fill with zero words, until reach 2nd to last slot
    while (this.xOff < (BLOCK_SIZE - 2)) {
      this.inwords[this.xOff] = 0;
      ++this.xOff;
    }

    // Store input data length in BITS
    this.inwords[this.xOff++] = (int)(bitLength >>> 32);
    this.inwords[this.xOff++] = (int)(bitLength);
  }

  private int P0(final int x) {
    final int r9  = ((x << 9)  | (x >>> (32 - 9)));
    final int r17 = ((x << 17) | (x >>> (32 - 17)));
    return (x ^ r9 ^ r17);
  }

  private int P1(final int x) {
    final int r15 = ((x << 15) | (x >>> (32 - 15)));
    final int r23 = ((x << 23) | (x >>> (32 - 23)));
    return (x ^ r15 ^ r23);
  }

  private int FF0(final int x, final int y, final int z) {
    return (x ^ y ^ z);
  }

  private int FF1(final int x, final int y, final int z) {
    return ((x & y) | (x & z) | (y & z));
  }

  private int GG0(final int x, final int y, final int z) {
    return (x ^ y ^ z);
  }

  private int GG1(final int x, final int y, final int z) {
    return ((x & y) | ((~x) & z));
  }

  private void processBlock() {
    System.arraycopy(this.inwords, 0, this.W, 0, 16);

    for (int j = 16; j < 68; ++j) {
      int wj3 = this.W[j - 3];
      int r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)));
      int wj13 = this.W[j - 13];
      int r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)));
      this.W[j] = P1(this.W[j - 16] ^ this.W[j - 9] ^ r15) ^ r7 ^ this.W[j - 6];
    }

    int A = this.V[0];
    int B = this.V[1];
    int C = this.V[2];
    int D = this.V[3];
    int E = this.V[4];
    int F = this.V[5];
    int G = this.V[6];
    int H = this.V[7];

    for (int j = 0; j < 16; ++j) {
      int a12 = ((A << 12) | (A >>> (32 - 12)));
      int s1_ = a12 + E + T[j];
      int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
      int SS2 = SS1 ^ a12;
      int Wj = W[j];
      int W1j = Wj ^ W[j + 4];
      int TT1 = FF0(A, B, C) + D + SS2 + W1j;
      int TT2 = GG0(E, F, G) + H + SS1 + Wj;
      D = C;
      C = ((B << 9) | (B >>> (32 - 9)));
      B = A;
      A = TT1;
      H = G;
      G = ((F << 19) | (F >>> (32 - 19)));
      F = E;
      E = P0(TT2);
    }

    // Different FF,GG functions on rounds 16..63
    for (int j = 16; j < 64; ++j) {
      int a12 = ((A << 12) | (A >>> (32 - 12)));
      int s1_ = a12 + E + T[j];
      int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
      int SS2 = SS1 ^ a12;
      int Wj = W[j];
      int W1j = Wj ^ W[j + 4];
      int TT1 = FF1(A, B, C) + D + SS2 + W1j;
      int TT2 = GG1(E, F, G) + H + SS1 + Wj;
      D = C;
      C = ((B << 9) | (B >>> (32 - 9)));
      B = A;
      A = TT1;
      H = G;
      G = ((F << 19) | (F >>> (32 - 19)));
      F = E;
      E = P0(TT2);
    }

    this.V[0] ^= A;
    this.V[1] ^= B;
    this.V[2] ^= C;
    this.V[3] ^= D;
    this.V[4] ^= E;
    this.V[5] ^= F;
    this.V[6] ^= G;
    this.V[7] ^= H;

    this.xOff = 0;
  }

}
