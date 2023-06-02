package org.krakenapps.pcap.decoder.http.h2;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ZipUtil;
import edu.baylor.cs.csi5321.spdy.frames.H2DataFrame;
import edu.baylor.cs.csi5321.spdy.frames.H2Frame;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameHeaders;
import org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream;
import org.krakenapps.pcap.decoder.http.HttpProcessor;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Set;

public class Http2Stream {

    private static final Logger log = LoggerFactory.getLogger(Http2Stream.class);

    final HttpSessionImpl session;
    final Set<HttpProcessor> callbacks;

    public Http2Stream(HttpSessionImpl session, Set<HttpProcessor> callbacks) {
        this.session = session;
        this.callbacks = callbacks;
    }

    private Http2RequestImpl request;

    public void handleRequestHeaders(H2FrameHeaders frameHeaders) {
        this.request = new Http2RequestImpl(session, frameHeaders.getHttp2Headers());
    }

    public void handleRequestData(H2DataFrame dataFrame) {
        request.buffer.addLast(dataFrame.getData());

        if (dataFrame.hasFlag(H2Frame.FLAG_END_STREAM)) {
            notifyRequest();
        }
    }

    private boolean requestNotified;

    private void notifyRequest() {
        if (requestNotified) {
            return;
        }
        requestNotified = true;
        for (HttpProcessor processor : callbacks) {
            processor.onRequest(session, request);
        }
    }

    private Http2ResponseImpl response;

    public void handleResponseHeaders(H2FrameHeaders frameHeaders) {
        this.response = new Http2ResponseImpl(frameHeaders.getHttp2Headers());
    }

    public boolean handleResponseData(H2DataFrame dataFrame) {
        response.buffer.addLast(dataFrame.getData());

        boolean finish = dataFrame.hasFlag(H2Frame.FLAG_END_STREAM);
        if (finish) {
            notifyRequest();
            notifyResponse();
        }
        return finish;
    }

    private void notifyResponse() {
        for (HttpProcessor processor : callbacks) {
            processor.onResponse(session, request, response);
        }
    }

    static byte[] extractBuffer(String contentEncoding, Buffer buffer) {
        byte[] data = new byte[buffer.readableBytes()];
        buffer.gets(data);
        try {
            if ("deflate".equalsIgnoreCase(contentEncoding)) {
                data = ZipUtil.unZlib(data);
            } else if ("gzip".equalsIgnoreCase(contentEncoding)) {
                data = ZipUtil.unGzip(data);
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                try (InputStream inputStream = new BrotliCompressorInputStream(new ByteArrayInputStream(data))) {
                    data = IoUtil.readBytes(inputStream);
                }
            } else if (contentEncoding != null) {
                log.warn("extractBuffer contentEncoding=" + contentEncoding + ", data=" + HexFormatter.encodeHexString(data));
            }
        } catch (Exception e) {
            log.warn("extractBuffer contentEncoding=" + contentEncoding + ", data=" + HexFormatter.encodeHexString(data), e);
        }
        return data;
    }

}
