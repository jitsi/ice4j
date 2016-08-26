/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.util;

import java.util.logging.*;

/**
 * Implements a logger, which delegates to a {@link java.util.logging.Logger}
 * instance, but maintains its own logging level.
 *
 * @author Boris Grozev
 */
public class Logger
{
    /**
     * The level of this logger.
     */
    private Level level;

    /**
     * The underlying {@link java.util.logging.Logger} instance to which logging
     * is delegated.
     */
    private java.util.logging.Logger delegate;

    /**
     * The {@link Logger} instance (if any) which provides the log level of this
     * instance.
     */
    private Logger levelDelegate;

    /**
     * Initializes a new {@link Logger} instance with a given delegate and a
     * given log level.
     * @param delegate the delegate.
     * @param level the log level.
     */
    public Logger(java.util.logging.Logger delegate, Level level)
    {
        this.delegate = delegate;
        this.level = level;
    }

    /**
     * Initializes a new {@link Logger} instance with a given delegate and which
     * uses the log level from another {@link Logger} instance.
     * @param delegate the delegate.
     * @param levelDelegate the {@link Logger} instance whose log level will be
     * used.
     */
    public Logger(java.util.logging.Logger delegate, Logger levelDelegate)
    {
        this.delegate = delegate;
        this.levelDelegate = levelDelegate;
    }

    /**
     * Sets the logging {@link Level} for this {@link Logger}.
     * @param level the level to set.
     */
    public void setLevel(Level level)
    {
        this.level = level;
    }

    /**
     * @return the logging {@link Level} configured for this {@link Logger}.
     */
    public Level getLevel()
    {
        return levelDelegate != null ? levelDelegate.getLevel() : level;
    }

    /**
     * Checks whether messages with a particular level should be logged
     * according to the log level configured for this {@link Logger}.
     * @param level the log level.
     */
    public boolean isLoggable(Level level)
    {
        Level currentLevel
            = levelDelegate != null ? levelDelegate.getLevel() : this.level;
        int levelValue = currentLevel.intValue();

        return level.intValue() >= levelValue
                && levelValue != Level.OFF.intValue();
    }

    /**
     * Logs a message at a given level, if that level is loggable according to
     * the log level configured by this instance.
     * @param level the level at which to log the message.
     * @param msg the message to log.
     */
    public void log(Level level, String msg)
    {
        if (isLoggable(level))
        {
            delegate.log(level, msg);
        }
    }

    /**
     * Logs a message at a given level, if that level is loggable according to
     * the log level configured by this instance.
     * @param level the level at which to log the message.
     * @param msg the message to log.
     * @param thrown a {@link Throwable} associated with log message.
     */
    public void log(Level level, String msg, Throwable thrown)
    {
        if (isLoggable(level))
        {
            delegate.log(level, msg, thrown);
        }
    }

    /**
     * Logs a message with level {@link Level#SEVERE}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void severe(String msg)
    {
        log(Level.SEVERE, msg);
    }

    /**
     * Logs a message with level {@link Level#WARNING}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void warning(String msg)
    {
        log(Level.WARNING, msg);
    }

    /**
     * Logs a message with level {@link Level#INFO}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void info(String msg)
    {
        log(Level.INFO, msg);
    }

    /**
     * Logs a message with level {@link Level#CONFIG}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void config(String msg)
    {
        log(Level.CONFIG, msg);
    }

    /**
     * Logs a message with level {@link Level#FINE}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void fine(String msg)
    {
        log(Level.FINE, msg);
    }

    /**
     * Logs a message with level {@link Level#FINER}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void finer(String msg)
    {
        log(Level.FINER, msg);
    }

    /**
     * Logs a message with level {@link Level#FINEST}, if that level is
     * loggable according to the log level configured for this {@link Logger}.
     * @param msg the message to log.
     */
    public void finest(String msg)
    {
        log(Level.FINEST, msg);
    }

    /**
     * An alias for {@link #fine(String)}.
     */
    public void debug(String msg)
    {
        fine(msg);
    }

    /**
     * An alias for {@link #warning(String)}.
     */
    public void warn(String msg)
    {
        warning(msg);
    }

    /**
     * An alias for {@link #severe(String)}.
     */
    public void error(String msg)
    {
        severe(msg);
    }

    /**
     * An alias for {@link #finest(String)}.
     */
    public void trace(String msg)
    {
        finest(msg);
    }
}
