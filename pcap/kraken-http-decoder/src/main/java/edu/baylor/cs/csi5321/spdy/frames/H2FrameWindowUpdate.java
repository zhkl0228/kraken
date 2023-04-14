/**
 * 
 */
package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * @author zhkl0228
 *
 */
public class H2FrameWindowUpdate extends SpdyFrameStream {

	public H2FrameWindowUpdate(boolean controlBit, byte flags, int length) throws SpdyException {
		super(controlBit, flags, length);
	}

	@Override
	public SpdyControlFrameType getType() {
		return SpdyControlFrameType.WINDOW_UPDATE;
	}

	@Override
	public byte[] encode() throws SpdyException {
		throw new UnsupportedOperationException();
	}
	
	private int deltaWindowSize;

	@Override
	public H2Frame decode(DataInputStream is) throws SpdyException {
		try {
			H2FrameWindowUpdate frame = (H2FrameWindowUpdate) super.decode(is);
			deltaWindowSize = is.readInt() & SpdyUtil.MASK_STREAM_ID_HEADER;
			return frame;
		} catch(IOException e) {
			throw new SpdyException(e);
		}
	}

	@Override
	public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
		deltaWindowSize = buffer.getInt() & SpdyUtil.MASK_STREAM_ID_HEADER;
	}

    @Override
	public String toString() {
		return getClass().getSimpleName() + " [streamId=" + streamId + ", deltaWindowSize=0x" + Integer.toHexString(deltaWindowSize) + "]";
	}

}
