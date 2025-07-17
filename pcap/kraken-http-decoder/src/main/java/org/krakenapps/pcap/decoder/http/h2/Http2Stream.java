package org.krakenapps.pcap.decoder.http.h2;

import edu.baylor.cs.csi5321.spdy.frames.H2DataFrame;
import edu.baylor.cs.csi5321.spdy.frames.H2Frame;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameHeaders;
import org.brotli.dec.BrotliInputStream;
import org.krakenapps.pcap.decoder.http.HttpProcessor;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

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

    public boolean handleResponseHeaders(H2FrameHeaders frameHeaders) {
        if (response == null) {
            response = new Http2ResponseImpl(frameHeaders.getHttp2Headers());
        } else {
            response.merge(frameHeaders.getHttp2Headers());
        }
        return checkEndStream(frameHeaders);
    }

    private boolean checkEndStream(H2Frame frame) {
        boolean finish = frame.hasFlag(H2Frame.FLAG_END_STREAM);
        if (finish) {
            notifyRequest();
            notifyResponse();
        }
        return finish;
    }

    public boolean handleResponseData(H2DataFrame dataFrame) {
        response.buffer.addLast(dataFrame.getData());
        return checkEndStream(dataFrame);
    }

    private void notifyResponse() {
        for (HttpProcessor processor : callbacks) {
            processor.onResponse(session, request, response);
        }
    }

    static byte[] extractBuffer(String contentEncoding, Buffer buffer) {
        byte[] data = new byte[buffer.readableBytes()];
        buffer.gets(data);
        if (data.length == 0) {
            return data;
        }
        try {
            if ("deflate".equalsIgnoreCase(contentEncoding)) {
                try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    Inflater inflater = new Inflater();
                    inflater.setInput(data);
                    byte[] buf = new byte[10240];
                    while (!inflater.finished()) {
                        int count = inflater.inflate(buf, 0, buf.length);
                        if(count > 0) {
                            baos.write(buf, 0, count);
                        } else {
                            break;
                        }
                    }
                    inflater.end();
                    data = baos.toByteArray();
                }
            } else if ("gzip".equalsIgnoreCase(contentEncoding)) {
                try(ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    InputStream inputStream = new GZIPInputStream(new ByteArrayInputStream(data))) {
                    byte[] buf = new byte[10240];
                    int read;
                    while ((read = inputStream.read(buf)) > 0) {
                        baos.write(buf, 0, read);
                    }
                    data = baos.toByteArray();
                }
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                try (InputStream inputStream = new BrotliInputStream(new ByteArrayInputStream(data));
                     ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[10240];
                    int read;
                    while ((read = inputStream.read(buf)) > 0) {
                        baos.write(buf, 0, read);
                    }
                    data = baos.toByteArray();
                }
            } else if (contentEncoding != null) {
                log.warn("extractBuffer contentEncoding={}, data={}", contentEncoding, HexFormatter.encodeHexString(data));
            }
        } catch (Exception e) {
            log.info("extractBufferFailed contentEncoding={}, data={}", contentEncoding, HexFormatter.encodeHexString(data));
        }
        return data;
    }

}
