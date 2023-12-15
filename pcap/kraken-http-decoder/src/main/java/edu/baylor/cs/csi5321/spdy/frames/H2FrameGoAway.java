package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

import java.nio.ByteBuffer;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameGoAway extends H2FrameRstStream {

    private static final int LENGTH = 8;

    public H2FrameGoAway(int streamId, boolean controlBit, byte flags, int length) throws H2Exception {
        super(streamId, controlBit, flags, length);
    }

    @Override
    public H2ControlFrameType getType() {
        return H2ControlFrameType.GOAWAY;
    }

    public long getLastGoodStreamId() {
        return getStreamId();
    }

    public void setLastGoodStreamId(int streamId) throws H2Exception {
        setStreamId(streamId);
    }

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws H2Exception {
        int streamId = buffer.getInt();
        setLastGoodStreamId(streamId & H2Util.MASK_STREAM_ID_HEADER);
        super.decode(impl, buffer);
    }

    @Override
    public int getLength() {
        return LENGTH;
    }
    
}
