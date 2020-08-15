package org.krakenapps.pcap.decoder.tcp;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.util.Buffer;

public interface ProtocolDetector {

    /**
     * Discover server protocol
     */
    Protocol detectProtocol(TcpSessionKey key, Buffer data);

}
