package org.krakenapps.pcap.decoder.http.impl;

import org.krakenapps.pcap.decoder.http.HttpRequest;
import org.krakenapps.pcap.decoder.http.HttpResponse;
import org.krakenapps.pcap.decoder.tcp.TcpSession;

/**
 * @author zhkl0228
 *
 */
public interface HttpSession extends TcpSession {

    HttpRequest getRequest();

    HttpResponse getResponse();

}
