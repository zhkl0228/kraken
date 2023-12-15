/**
 * 
 */
package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * @author zhkl0228
 *
 */
public class H2FramePing extends H2ControlFrame {
	
	private static final Logger log = LoggerFactory.getLogger(H2FramePing.class);

	public H2FramePing(boolean controlBit, byte flags, int length) throws H2Exception {
		super(controlBit, flags, length);
	}

	@Override
	public H2ControlFrameType getType() {
		return H2ControlFrameType.PING;
	}

	@Override
	public byte[] encode() throws H2Exception {
		throw new UnsupportedOperationException();
	}

	@Override
	public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws H2Exception {
		long pingId = buffer.getLong();
		log.debug("decode pingId=0x" + Long.toHexString(pingId));
	}

	/* (non-Javadoc)
	 * @see edu.baylor.cs.csi5321.spdy.frames.SpdyFrame#decode(java.io.DataInputStream)
	 */
	@Override
	public H2Frame decode(DataInputStream is) throws H2Exception {
		try {
			int pingId = is.readInt();
			log.debug("decode pingId=" + pingId);
			return this;
		} catch(IOException e) {
			throw new H2Exception(e);
		}
	}

}
