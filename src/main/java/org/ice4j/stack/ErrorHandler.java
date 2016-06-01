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
package org.ice4j.stack;

/**
 * Generic Error Handler.
 *
 * @author Emil Ivov
 */
interface ErrorHandler
{
    /**
     * Called when an error has occurred which may have caused data loss but the
     * calling thread is still running.
     *
     * @param message A message describing the error
     * @param error   The error itself.
     */
    public void handleError(String message, Throwable error);

    /**
     * Called when a fatal error has occurred and the calling thread will exit.
     *
     * @param callingThread the thread where the error has occurred
     * @param message       a message describing the error.
     * @param error         the error itself.
     */
    public void handleFatalError(Runnable callingThread,
                                 String message,
                                 Throwable error);
}
