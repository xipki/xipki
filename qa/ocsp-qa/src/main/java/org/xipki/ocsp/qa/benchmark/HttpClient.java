/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.qa.benchmark;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.client.api.OcspRequestorException;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.concurrent.CountLatch;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

final class HttpClient implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

  private class HttpClientInitializer extends ChannelInitializer<SocketChannel> {

    public HttpClientInitializer() {
    }

    @Override
    public void initChannel(SocketChannel ch) {
      ch.pipeline()
        .addLast(new ReadTimeoutHandler(60, TimeUnit.SECONDS))
        .addLast(new WriteTimeoutHandler(60, TimeUnit.SECONDS))
        .addLast(new HttpClientCodec())
        .addLast(new HttpObjectAggregator(4096))
        .addLast(new HttpClientHandler());
    }
  }

  private class HttpClientHandler extends SimpleChannelInboundHandler<FullHttpResponse> {

    @Override
    public void channelRead0(ChannelHandlerContext ctx, FullHttpResponse resp) {
      try {
        decrementPendingRequests();
        responseHandler.onComplete(resp);
      } catch (RuntimeException ex) {
        LOG.error("unexpected error", ex);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
      decrementPendingRequests();
      ctx.close();
      LOG.warn("error", cause);
      responseHandler.onError();
    }
  }

  private static Boolean epollAvailable;

  private static Boolean kqueueAvailable;

  private final CountLatch latch = new CountLatch(0, 0);

  private int queueSize = 1000;

  private URI uri;

  private String host;

  private OcspBenchmark responseHandler;

  private EventLoopGroup workerGroup;

  private Channel channel;

  private int pendingRequests = 0;

  static {
    String os = System.getProperty("os.name").toLowerCase();
    ClassLoader loader = HttpClient.class.getClassLoader();
    if (os.contains("linux")) {
      try {
        Class<?> checkClazz = clazz("io.netty.channel.epoll.Epoll", false, loader);
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
        Class<?> checkClazz = clazz("io.netty.channel.epoll.kqueue.KQueue", false, loader);
        Method mt = checkClazz.getMethod("isAvailable");
        Object obj = mt.invoke(null);
        if (obj instanceof Boolean) {
          kqueueAvailable = (Boolean) obj;
        }
      } catch (Throwable th) {
        LogUtil.warn(LOG, th, "could not use KQueue transport");
      }
    }
  }

  public HttpClient(URI uri, OcspBenchmark responseHandler, int queueSize) {
    this.uri = ParamUtil.requireNonNull("uri", uri);
    this.host = uri.getHost() + ":" + uri.getPort();
    if (queueSize > 0) {
      this.queueSize = queueSize;
    }
    this.responseHandler = ParamUtil.requireNonNull("responseHandler", responseHandler);
    this.workerGroup = new NioEventLoopGroup(1);
  }

  @SuppressWarnings("unchecked")
  public void start() throws Exception {
    String scheme = (uri.getScheme() == null) ? "http" : uri.getScheme();

    if (!"http".equalsIgnoreCase(scheme)) {
      System.err.println("Only HTTP is supported.");
      return;
    }

    int port = uri.getPort();
    if (port == -1) {
      port = 80;
    }

    Class<? extends SocketChannel> channelClass = NioSocketChannel.class;

    final int numThreads = 1;

    ClassLoader loader = getClass().getClassLoader();
    if (epollAvailable != null && epollAvailable.booleanValue()) {
      try {
        channelClass = (Class<? extends SocketChannel>)
            clazz("io.netty.channel.epoll.EpollSocketChannel", false, loader);

        Class<?> clazz = clazz("io.netty.channel.epoll.EpollEventLoopGroup", true, loader);
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
                clazz("io.netty.channel.kqueue.KQueueSocketChannel", false, loader);

        Class<?> clazz = clazz("io.netty.channel.kqueue.KQueueEventLoopGroup", true, loader);
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
      .handler(new HttpClientInitializer());

    String host = (uri.getHost() == null) ? "127.0.0.1" : uri.getHost();

    // Make the connection attempt.
    this.channel = bootstrap.connect(host, port).syncUninterruptibly().channel();

    long start = System.currentTimeMillis();
    while (!this.channel.isActive() && System.currentTimeMillis() - start < 1000) {
      LOG.info("channel is not active, waiting for 100 ms");
      Thread.sleep(100);
    }

    if (!this.channel.isActive()) {
      throw new IOException("coult not open and activate channel");
    }
  }

  public void send(FullHttpRequest request) throws OcspRequestorException {
    if (!channel.isActive()) {
      throw new OcspRequestorException("channel is not active");
    }

    request.headers().add(HttpHeaderNames.HOST, host);

    try {
      latch.await(5, TimeUnit.SECONDS);
    } catch (InterruptedException ex) {
      throw new OcspRequestorException("sending poll is full");
    }
    incrementPendingRequests();
    ChannelFuture future = this.channel.writeAndFlush(request);
    future.awaitUninterruptibly();
  }

  @Deprecated
  public void shutdown() {
    close();
  }

  @Override
  public void close() {
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
  }

  private static Class<?> clazz(String clazzName, boolean initialize, ClassLoader clazzLoader)
      throws ClassNotFoundException {
    return Class.forName(clazzName, initialize, clazzLoader);
  }

}
