package org.krakenapps.pcap.decoder.http.h2;

import edu.baylor.cs.csi5321.spdy.frames.H2DataFrame;
import edu.baylor.cs.csi5321.spdy.frames.H2Frame;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameHeaders;
import org.krakenapps.pcap.decoder.http.HttpProcessor;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

import java.util.Set;

public class Http2Stream {

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

}
