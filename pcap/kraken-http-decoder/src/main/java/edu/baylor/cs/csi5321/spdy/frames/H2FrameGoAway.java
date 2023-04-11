package edu.baylor.cs.csi5321.spdy.frames;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameGoAway extends H2FrameRstStream {
	
	private static final int OK = 0;
	private static final int PROTOCOL_ERROR = 1;
	private static final int INTERNAL_ERROR = 2;

    private static final int LENGTH = 8;
    public static final Integer[] STATUS_CODES = new Integer[] { OK, PROTOCOL_ERROR, INTERNAL_ERROR };

    public H2FrameGoAway(int statusCode, int streamId, boolean controlBit, byte flags) throws SpdyException {
        super(statusCode, streamId, controlBit, flags);
    }

    public H2FrameGoAway(boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
    }

    @Override
    public SpdyControlFrameType getType() {
        return SpdyControlFrameType.GOAWAY;
    }

    public long getLastGoodStreamId() {
        return getStreamId();
    }

    public void setLastGoodStreamId(int streamId) throws SpdyException {
        setStreamId(streamId);
    }

    @Override
    public int getLength() {
        return LENGTH;
    }
    
    @Override
    public Integer[] getValidStatusCodes() {
        return STATUS_CODES;
    }
    
}
