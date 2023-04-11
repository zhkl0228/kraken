package org.krakenapps.pcap.decoder.http;

import org.krakenapps.pcap.decoder.http.impl.HttpSession;

public interface WebSocketProcessor {

    /**
     * on websocket handshake success
     */
    void onWebSocketHandshake(HttpSession session, HttpRequest request, HttpResponse response);

    void onWebSocketRequest(HttpSession session, WebSocketFrame frame);
    void onWebSocketResponse(HttpSession session, WebSocketFrame frame);

}
