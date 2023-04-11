package edu.baylor.cs.csi5321.spdy.frames;

/**
 *
 * @author Lukas Camra
 */
public class SpdyException extends Exception {

    public static final long serialVersionUID = -238502093295259L;

    public SpdyException(String message) {
        super(message);
    }

    public SpdyException(String message, Throwable cause) {
        super(message, cause);
    }

    public SpdyException(Throwable cause) {
        super(cause);
    }
}
