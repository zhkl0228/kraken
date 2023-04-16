package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class H2PriorityFrame extends SpdyFrameStream {

    private static final Logger log = LoggerFactory.getLogger(H2PriorityFrame.class);

    public H2PriorityFrame(int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(streamId, controlBit, flags, length);
    }

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
        int streamDependency = buffer.getInt();
        boolean exclusive = streamDependency >>> 31 != 0;
        int associatedToStreamId = streamDependency & SpdyUtil.MASK_STREAM_ID_HEADER;
        int weight = buffer.get() & 0xff;
        log.debug("decode exclusive={}, associatedToStreamId={}, weight={}", new Object[] {
                exclusive, associatedToStreamId, weight
        });
    }

    @Override
    public SpdyControlFrameType getType() {
        return SpdyControlFrameType.PRIORITY;
    }

}
