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
public class H2FrameWindowUpdate extends H2FrameStream {

	public H2FrameWindowUpdate(boolean controlBit, byte flags, int length) throws H2Exception {
		super(controlBit, flags, length);
	}

	@Override
	public H2ControlFrameType getType() {
		return H2ControlFrameType.WINDOW_UPDATE;
	}

	@Override
	public byte[] encode() throws H2Exception {
		throw new UnsupportedOperationException();
	}
	
	private int deltaWindowSize;

	@Override
	public H2Frame decode(DataInputStream is) throws H2Exception {
		try {
			H2FrameWindowUpdate frame = (H2FrameWindowUpdate) super.decode(is);
			deltaWindowSize = is.readInt() & H2Util.MASK_STREAM_ID_HEADER;
			return frame;
		} catch(IOException e) {
			throw new H2Exception(e);
		}
	}

	@Override
	public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws H2Exception {
		deltaWindowSize = buffer.getInt() & H2Util.MASK_STREAM_ID_HEADER;
	}

    @Override
	public String toString() {
		return getClass().getSimpleName() + " [streamId=" + streamId + ", deltaWindowSize=0x" + Integer.toHexString(deltaWindowSize) + "]";
	}

}
