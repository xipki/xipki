/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.http.server;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerSocketChannel;
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

    private static boolean useEpollLinux;

    private final int port;

    private final SslContext sslContext;

    private final int numThreads;

    private ServletListener servletListener;

    private EventLoopGroup bossGroup;

    private EventLoopGroup workerGroup;

    static {
        boolean linux = System.getProperty("os.name").toLowerCase().contains("linux");
        useEpollLinux = linux ? Epoll.isAvailable() : false;
        LOG.info("linux epoll available: {}", useEpollLinux);
    }

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

    public void start() {
        int numProcessors = Runtime.getRuntime().availableProcessors();
        Class<? extends ServerSocketChannel> channelClass;
        int bossGroupThreads = (numProcessors == 1) ? 1 : numProcessors - 1;
        if (useEpollLinux) {
            channelClass = EpollServerSocketChannel.class;
            this.bossGroup = new EpollEventLoopGroup(bossGroupThreads);
            this.workerGroup = new EpollEventLoopGroup(numThreads);
        } else {
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
