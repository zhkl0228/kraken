/**
 * 
 */
package edu.baylor.cs.csi5321.spdy.frames;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * @author zhkl0228
 *
 */
public class H2FramePing extends SpdyControlFrame {
	
	private static final Logger log = LoggerFactory.getLogger(H2FramePing.class);

	public H2FramePing(boolean controlBit, byte flags, int length) throws SpdyException {
		super(controlBit, flags, length);
	}

	@Override
	public SpdyControlFrameType getType() {
		return SpdyControlFrameType.PING;
	}

	@Override
	public byte[] encode() throws SpdyException {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see edu.baylor.cs.csi5321.spdy.frames.SpdyFrame#decode(java.io.DataInputStream)
	 */
	@Override
	public H2Frame decode(DataInputStream is) throws SpdyException {
		try {
			int pingId = is.readInt();
			log.debug("decode pingId=" + pingId);
			return this;
		} catch(IOException e) {
			throw new SpdyException(e);
		}
	}

}
