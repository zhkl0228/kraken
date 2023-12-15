package edu.baylor.cs.csi5321.spdy.frames;

/**
 *
 * @author Lukas Camra
 */
public class H2Exception extends Exception {

    public static final long serialVersionUID = -238502093295259L;

    public H2Exception(String message) {
        super(message);
    }

    public H2Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public H2Exception(Throwable cause) {
        super(cause);
    }
}
