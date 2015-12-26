package org.bsworks.misc.xrds;


/**
 * Interface for a logger used by the XRDS factory to log debug messages.
 *
 * @author Lev Himmelfarb
 */
public interface DebugLogger {

	/**
	 * Tell if debug logging is enabled.
	 *
	 * @return {@code true} if enabled.
	 */
	boolean isEnabled();

	/**
	 * Log a debug message.
	 *
	 * @param message The message.
	 */
	void log(String message);

	/**
	 * Log a debug message with an attached throwable.
	 *
	 * @param message The message.
	 * @param throwable The throwable.
	 */
	void log(String message, Throwable throwable);
}
