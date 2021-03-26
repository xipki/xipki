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

package org.xipki.qa;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.InvalidConfException;
import org.xipki.util.LogUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.concurrent.CountLatch;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

import static org.xipki.util.Args.notNull;

/**
 * Benchmark HTTP client.
 *
 * @author Lijun Liao
 */

public class BenchmarkHttpClient {

  public static class SslConf extends ValidatableConf {

    private String storeType;

    private String keystore;

    private String keystorePassword;

    private String truststore;

    private String truststorePassword;

    private SslContext sslContext;

    public String getStoreType() {
      return storeType;
    }

    public void setStoreType(String storeType) {
      this.storeType = storeType;
    }

    public String getKeystore() {
      return keystore;
    }

    public void setKeystore(String keystore) {
      this.keystore = keystore;
    }

    public String getKeystorePassword() {
      return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
      this.keystorePassword = keystorePassword;
    }

    public String getTruststore() {
      return truststore;
    }

    public void setTruststore(String truststore) {
      this.truststore = truststore;
    }

    public String getTruststorePassword() {
      return truststorePassword;
    }

    public void setTruststorePassword(String truststorePassword) {
      this.truststorePassword = truststorePassword;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

    public SslContext buildSslContext()
        throws GeneralSecurityException, IOException {
      if (sslContext != null) {
        return sslContext;
      }

      SslContextBuilder builder = SslContextBuilder.forClient();

      // key and certificate
      if (keystore != null) {
        char[] pwd = keystorePassword == null ? null : keystorePassword.toCharArray();
        KeyStore ks = loadKeyStore(storeType, keystore, pwd);
        Enumeration<String> aliases = ks.aliases();

        boolean foundKey = false;
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (!ks.isKeyEntry(alias)) {
            continue;
          }

          foundKey = true;
          PrivateKey key = (PrivateKey) ks.getKey(alias, pwd);
          Certificate[] certs = ks.getCertificateChain(alias);
          X509Certificate[] keyCertChain = new X509Certificate[certs.length];
          for (int i = 0; i < certs.length; i++) {
            keyCertChain[i] = (X509Certificate) certs[i];
          }

          builder.keyManager(key, alias, keyCertChain);
        }

        if (!foundKey) {
          throw new GeneralSecurityException("found no key entries in the keystore " + keystore);
        }
      }

      if (truststore != null) {
        char[] pwd = truststorePassword == null ? null : truststorePassword.toCharArray();
        KeyStore ks = loadKeyStore(storeType, truststore, pwd);
        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          Certificate cert = ks.getCertificate(alias);
          if (cert instanceof X509Certificate) {
            builder.trustManager((X509Certificate) cert);
          }
        }
      }

      // providers
      SslProvider sslProvider = OpenSsl.isAvailable()
          ? SslProvider.OPENSSL : SslContext.defaultServerProvider();
      System.out.println("use SSL provider " + sslProvider);
      builder.sslProvider(sslProvider);

      // protocols
      builder.protocols("TLSv1.1", "TLSv1.2");

      sslContext = builder.build();
      return sslContext;
    } // method buildSslContext

    private static KeyStore loadKeyStore(String storeType, String store, char[] password)
        throws GeneralSecurityException, IOException {
      if (storeType == null) {
        storeType = "JCEKS";
      }

      try (InputStream stream = Files.newInputStream(Paths.get(store))) {
        KeyStore keystore = KeyStore.getInstance(storeType);
        keystore.load(stream, password);
        return keystore;
      }
    } // method loadKeyStore

  } // class SslConf

  private static final Logger LOG = LoggerFactory.getLogger(BenchmarkHttpClient.class);

  public static interface ResponseHandler {

    void onComplete(FullHttpResponse response);

    void onError();

  } // class ResponseHandler

  public static class HttpClientException extends Exception {

    private static final long serialVersionUID = 1L;

    public HttpClientException(String message) {
      super(message);
    }

    public HttpClientException(String message, Throwable cause) {
      super(message, cause);
    }

  } // class HttpClientException

  private class HttpClientInitializer extends ChannelInitializer<SocketChannel> {

    private SslContext sslContext;

    public HttpClientInitializer(SslContext sslContext) {
      this.sslContext = sslContext;
    }

    @Override
    public void initChannel(SocketChannel ch) {
      ChannelPipeline pipeline = ch.pipeline();

      if (sslContext != null) {
        pipeline.addLast("ssl", sslContext.newHandler(ch.alloc()));
      }

      pipeline.addLast(new ReadTimeoutHandler(60, TimeUnit.SECONDS))
        .addLast(new WriteTimeoutHandler(60, TimeUnit.SECONDS))
        .addLast(new HttpClientCodec())
        .addLast(new HttpObjectAggregator(65536))
        .addLast(new HttpClientHandler());
    }
  }

  private class HttpClientHandler extends SimpleChannelInboundHandler<FullHttpResponse> {

    @Override
    public void channelRead0(ChannelHandlerContext ctx, FullHttpResponse resp) {
      try {
        decrementPendingRequests();
        responseHandler.onComplete(resp);
      } catch (Throwable th) {
        LOG.error("unexpected error", th);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      decrementPendingRequests();
      ctx.close();
      LOG.warn("error", cause);
      responseHandler.onError();
    }
  } // method HttpClientHandler

  private static Boolean epollAvailable;

  private static Boolean kqueueAvailable;

  private final CountLatch latch = new CountLatch(0, 0);

  private int queueSize = 1000;

  private ResponseHandler responseHandler;

  private EventLoopGroup workerGroup;

  private Channel channel;

  private SslContext sslContext;

  private int pendingRequests = 0;

  private String host;

  private int port;

  private String hostHeader;

  static {
    String os = System.getProperty("os.name").toLowerCase();
    ClassLoader loader = BenchmarkHttpClient.class.getClassLoader();
    if (os.contains("linux")) {
      try {
        Class<?> checkClazz = Class.forName("io.netty.channel.epoll.Epoll", false, loader);
        Method mt = checkClazz.getMethod("isAvailable");
        Object obj = mt.invoke(null);

        if (obj instanceof Boolean) {
          epollAvailable = (Boolean) obj;
        }
      } catch (Throwable th) {
        if (th instanceof ClassNotFoundException) {
          LOG.info("epoll linux is not in classpath");
        } else {
          LogUtil.warn(LOG, th, "could not use Epoll transport");
        }
      }
    } else if (os.contains("mac os") || os.contains("os x")) {
      try {
        Class<?> checkClazz = Class.forName("io.netty.channel.epoll.kqueue.KQueue", false, loader);
        Method mt = checkClazz.getMethod("isAvailable");
        Object obj = mt.invoke(null);
        if (obj instanceof Boolean) {
          kqueueAvailable = (Boolean) obj;
        }
      } catch (Throwable th) {
        LogUtil.warn(LOG, th, "could not use KQueue transport");
      }
    }
  } // method static

  public BenchmarkHttpClient(String host, int port, SslContext sslContext,
      ResponseHandler responseHandler, int queueSize) {
    this.sslContext = sslContext;
    if (queueSize > 0) {
      this.queueSize = queueSize;
    }
    this.responseHandler = notNull(responseHandler, "responseHandler");
    this.workerGroup = new NioEventLoopGroup(1);
    this.host = host;
    this.port = port;
    this.hostHeader = host + ":" + port;
  }

  @SuppressWarnings("unchecked")
  public void start() {
    Class<? extends SocketChannel> channelClass = NioSocketChannel.class;

    final int numThreads = 1;

    ClassLoader loader = getClass().getClassLoader();
    if (epollAvailable != null && epollAvailable.booleanValue()) {
      try {
        channelClass = (Class<? extends SocketChannel>)
            Class.forName("io.netty.channel.epoll.EpollSocketChannel", false, loader);

        Class<?> clazz = Class.forName("io.netty.channel.epoll.EpollEventLoopGroup", true, loader);
        Constructor<?> constructor = clazz.getConstructor(int.class);
        this.workerGroup = (EventLoopGroup) constructor.newInstance(numThreads);
        LOG.info("use Epoll Transport");
      } catch (Throwable th) {
        if (th instanceof ClassNotFoundException) {
          LOG.info("epoll linux is not in classpath");
        } else {
          LogUtil.warn(LOG, th, "could not use Epoll transport");
        }
        channelClass = null;
        this.workerGroup = null;
      }
    } else if (kqueueAvailable != null && kqueueAvailable.booleanValue()) {
      try {
        channelClass = (Class<? extends SocketChannel>)
                Class.forName("io.netty.channel.kqueue.KQueueSocketChannel", false, loader);

        Class<?> clazz = Class.forName("io.netty.channel.kqueue.KQueueEventLoopGroup",
                    true, loader);
        Constructor<?> constructor = clazz.getConstructor(int.class);
        this.workerGroup = (EventLoopGroup) constructor.newInstance(numThreads);
        LOG.info("Use KQueue Transport");
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, "could not use KQueue transport");
        channelClass = null;
        this.workerGroup = null;
      }
    }

    if (this.workerGroup == null) {
      channelClass = NioSocketChannel.class;
      this.workerGroup = new NioEventLoopGroup(numThreads);
    }

    Bootstrap bootstrap = new Bootstrap();
    bootstrap.group(workerGroup)
      .option(ChannelOption.SO_KEEPALIVE, true)
      .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 60000)
      .channel(channelClass)
      .handler(new HttpClientInitializer(sslContext));

    // Make the connection attempt.
    this.channel = bootstrap.connect(host, port).syncUninterruptibly().channel();
  } // method start

  public void send(FullHttpRequest request)
      throws HttpClientException {
    request.headers().add(HttpHeaderNames.HOST, hostHeader);
    if (!channel.isActive()) {
      throw new HttpClientException("channel is not active");
    }

    try {
      latch.await(5, TimeUnit.SECONDS);
    } catch (InterruptedException ex) {
      throw new HttpClientException("sending poll is full");
    }
    incrementPendingRequests();
    ChannelFuture future = this.channel.writeAndFlush(request);
    future.awaitUninterruptibly();
  }

  public void shutdown() {
    if (channel != null) {
      channel = null;
    }
    this.workerGroup.shutdownGracefully();
  }

  private void incrementPendingRequests() {
    synchronized (latch) {
      if (++pendingRequests >= queueSize) {
        if (latch.getCount() == 0) {
          latch.countUp();
        }
      }
    }
  }

  private void decrementPendingRequests() {
    synchronized (latch) {
      if (--pendingRequests < queueSize) {
        final int count = (int) latch.getCount();
        if (count > 0) {
          while (latch.getCount() != 0) {
            latch.countDown();
          }
        } else if (count < 0) {
          while (latch.getCount() != 0) {
            latch.countUp();
          }
        }
      }
    }
  } // method decrementPendingRequests

}
