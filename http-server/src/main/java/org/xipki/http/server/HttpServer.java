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

package org.xipki.http.server;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.http.servlet.HttpServlet;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.CharsetUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public final class HttpServer {

    private class NettyHttpServerInitializer extends ChannelInitializer<SocketChannel> {

        public NettyHttpServerInitializer() {
        }

        @Override
        public void initChannel(SocketChannel ch) {
            ChannelPipeline pipeline = ch.pipeline();
            if (sslContext != null) {
                pipeline.addLast("ssl", sslContext.newHandler(ch.alloc()));
            }
            pipeline.addLast(new HttpServerCodec())
                .addLast(new HttpObjectAggregator(65536))
                .addLast(new ChunkedWriteHandler())
                .addLast(new NettyHttpServerHandler());
        }
    }

    private class NettyHttpServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

        private NettyHttpServerHandler() {
            super(true);
        }

        @Override
        public void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request)
                throws Exception {
            if (!request.decoderResult().isSuccess()) {
                sendError(ctx, HttpResponseStatus.BAD_REQUEST);
                return;
            }

            Object[] objs = servletListener.getServlet(request.uri());
            if (objs== null) {
                sendError(ctx, HttpResponseStatus.NOT_FOUND);
                return;
            }

            ServletURI servletUri = (ServletURI) objs[0];
            HttpServlet servlet = (HttpServlet) objs[1];

            SSLSession sslSession = null;

            if (servlet.needsTlsSessionInfo() && sslContext != null) {
                SslHandler handler = (SslHandler) ctx.channel().pipeline().get("ssl");
                if (handler != null) {
                    sslSession = handler.engine().getSession();
                }
            }

            FullHttpResponse response;
            try {
                response = servlet.service(request, servletUri, sslSession, sslReverseProxyMode);
            } catch (Exception ex) {
                logException("exception raised while processing request", ex);
                sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR);
                return;
            }

            boolean keepAlive = true;
            int status = response.status().code();
            if (status < 200 | status > 299) {
                keepAlive = false;
            }

            ChannelFuture cf = ctx.writeAndFlush(response);
            if (!keepAlive) {
                cf.addListener(ChannelFutureListener.CLOSE);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (ctx.channel().isActive()) {
                sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR);
            }
        }

        private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
            ByteBuf content = Unpooled.copiedBuffer("Failure: " + status + "\r\n",
                    CharsetUtil.UTF_8);
            FullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, status, content);
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");

            // Close the connection as soon as the error message is sent.
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }

        private void logException(String msg, Exception ex) {
            LOG.warn("{} - {}: {}", msg, ex.getClass().getName(), ex.getMessage());
            LOG.debug(msg, ex);
            return;
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(HttpServer.class);

    private static Boolean epollAvailable;

    private static Boolean kqueueAvailable;

    private final int port;

    private final SslContext sslContext;

    private final int numThreads;

    private ServletListener servletListener;

    private EventLoopGroup bossGroup;

    private EventLoopGroup workerGroup;

    private SslReverseProxyMode sslReverseProxyMode = SslReverseProxyMode.NONE;

    public void setSslReverseProxyMode(SslReverseProxyMode mode) {
        this.sslReverseProxyMode = (mode == null) ? SslReverseProxyMode.NONE : mode;
    }

    public HttpServer(SslContext sslContext, int port, int numThreads) {
        this.sslContext = sslContext;
        this.port = port;
        if (numThreads > 0) {
            this.numThreads = numThreads;
        } else {
            this.numThreads = 4 * Runtime.getRuntime().availableProcessors();
        }
    }

    public void setServletListener(ServletListener servletListener) {
        this.servletListener = servletListener;
    }

    static {
        String os = System.getProperty("os.name").toLowerCase();
        ClassLoader loader = HttpServer.class.getClassLoader();
        if (os.contains("linux")) {
            try {
                Class<?> checkClazz = Class.forName(
                        "io.netty.channel.epoll.Epoll", false, loader);
                Method mt = checkClazz.getMethod("isAvailable");
                Object obj = mt.invoke(null);

                if (obj instanceof Boolean) {
                    epollAvailable = (Boolean) obj;
                }
            } catch (Throwable th) {
                if (th instanceof ClassNotFoundException) {
                    LOG.info("epoll linux is not in classpath");
                } else {
                    LOG.warn("could not use Epoll transport: {}", th.getMessage());
                    LOG.debug("could not use Epoll transport", th);
                }
            }
        } else if (os.contains("mac os") || os.contains("os x")) {
            try {
                Class<?> checkClazz = Class.forName(
                        "io.netty.channel.epoll.kqueue.KQueue", false, loader);
                Method mt = checkClazz.getMethod("isAvailable");
                Object obj = mt.invoke(null);
                if (obj instanceof Boolean) {
                    kqueueAvailable = (Boolean) obj;
                }
            } catch (Exception ex) {
                LOG.warn("could not use KQueue transport: {}", ex.getMessage());
                LOG.debug("could not use KQueue transport", ex);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void start() {
        int numProcessors = Runtime.getRuntime().availableProcessors();
        Class<? extends ServerSocketChannel> channelClass = null;
        int bossGroupThreads = numProcessors == 1 ? 1  : (numProcessors + 1)/ 2;

        ClassLoader loader = getClass().getClassLoader();
        if (epollAvailable != null && epollAvailable.booleanValue()) {
            try {
                channelClass = (Class<? extends ServerSocketChannel>)
                        Class.forName("io.netty.channel.epoll.EpollServerSocketChannel",
                                false, loader);

                Class<?> clazz = Class.forName("io.netty.channel.epoll.EpollEventLoopGroup",
                                    true, loader);
                Constructor<?> constructor = clazz.getConstructor(int.class);
                this.bossGroup = (EventLoopGroup) constructor.newInstance(bossGroupThreads);
                this.workerGroup = (EventLoopGroup) constructor.newInstance(numThreads);
                LOG.info("use Epoll Transport");
            } catch (Throwable th) {
                if (th instanceof ClassNotFoundException) {
                    LOG.info("epoll linux is not in classpath");
                } else {
                    LogUtil.warn(LOG, th, "could not use Epoll transport");
                }
                channelClass = null;
                this.bossGroup = null;
                this.workerGroup = null;
            }
        } else if (kqueueAvailable != null && kqueueAvailable.booleanValue()) {
            try {
                channelClass = (Class<? extends ServerSocketChannel>)
                        Class.forName("io.netty.channel.kqueue.KQueueServerSocketChannel",
                                false, loader);

                Class<?> clazz = Class.forName("io.netty.channel.kqueue.KQueueEventLoopGroup",
                                    true, loader);
                Constructor<?> constructor = clazz.getConstructor(int.class);
                this.bossGroup = (EventLoopGroup) constructor.newInstance(bossGroupThreads);
                this.workerGroup = (EventLoopGroup) constructor.newInstance(numThreads);
                LOG.info("Use KQueue Transport");
            } catch (Exception ex) {
                LOG.warn("could not use KQueue transport: {}", ex.getMessage());
                LOG.debug("could not use KQueue transport", ex);
                channelClass = null;
                this.bossGroup = null;
                this.workerGroup = null;
            }
        }

        if (this.bossGroup == null) {
            channelClass = NioServerSocketChannel.class;
            this.bossGroup = new NioEventLoopGroup(bossGroupThreads);
            this.workerGroup = new NioEventLoopGroup(numThreads);
        }

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
            .channel(channelClass)
            .handler(new LoggingHandler())
            .childHandler(new NettyHttpServerInitializer());

        bootstrap.bind(port).syncUninterruptibly();
        LOG.info("HTTP server is listening on port {}", port);
    }

    public void shutdown() {
        bossGroup.shutdownGracefully();
        bossGroup = null;
        workerGroup.shutdownGracefully();
        workerGroup = null;
    }
}
