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

package org.xipki.ocsp.qa.benchmark;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.concurrent.CountLatch;
import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.client.api.OcspRequestorException;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

final class HttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

    private static boolean useEpollLinux;

    private class HttpClientInitializer extends ChannelInitializer<SocketChannel> {

        public HttpClientInitializer() {
        }

        @Override
        public void initChannel(SocketChannel ch) {
            ChannelPipeline pipeline = ch.pipeline();
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
    }

    private static final int MAX_PENDING_REQUESTS = 1000;

    private String uri;

    private OcspBenchmark responseHandler;

    private EventLoopGroup workerGroup;

    private Channel channel;

    private int pendingRequests = 0;

    private final CountLatch latch = new CountLatch(0, 0);

    static {
        boolean linux = System.getProperty("os.name").toLowerCase().contains("linux");
        useEpollLinux = linux ? Epoll.isAvailable() : false;
        LOG.info("linux epoll available: {}", useEpollLinux);
    }

    public HttpClient(String uri, OcspBenchmark responseHandler) {
        this.uri = ParamUtil.requireNonNull("uri", uri);
        this.responseHandler = ParamUtil.requireNonNull("responseHandler", responseHandler);
        final int n = Runtime.getRuntime().availableProcessors();
        this.workerGroup = useEpollLinux ? new EpollEventLoopGroup(n) : new NioEventLoopGroup(n);
    }

    public void start() throws Exception {
        URI uri = new URI(this.uri);
        String scheme = (uri.getScheme() == null) ? "http" : uri.getScheme();
        String host = (uri.getHost() == null) ? "127.0.0.1" : uri.getHost();
        int port = uri.getPort();
        if (port == -1) {
            if ("http".equalsIgnoreCase(scheme)) {
                port = 80;
            }
        }

        if (!"http".equalsIgnoreCase(scheme)) {
            System.err.println("Only HTTP is supported.");
            return;
        }

        Class<? extends SocketChannel> channelClass;
        // Configure the client.
        if (workerGroup instanceof EpollEventLoopGroup) {
            channelClass = EpollSocketChannel.class;
        } else {
            channelClass = NioSocketChannel.class;
        }

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(workerGroup)
            .option(ChannelOption.SO_KEEPALIVE, true)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 60000)
            .channel(channelClass)
            .handler(new HttpClientInitializer());

        // Make the connection attempt.
        this.channel = bootstrap.connect(host, port).syncUninterruptibly().channel();
    }

    public void send(FullHttpRequest request) throws OcspRequestorException {
        if (!channel.isActive()) {
            throw new OcspRequestorException("channel is not active");
        }

        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            throw new OcspRequestorException("sending poll is full");
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
            if (++pendingRequests >= MAX_PENDING_REQUESTS){
                latch.countUp();
            }
        }
    }

    private void decrementPendingRequests() {
        synchronized (latch) {
            if (--pendingRequests < MAX_PENDING_REQUESTS){
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
}
