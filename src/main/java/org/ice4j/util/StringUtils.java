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

/**
 * Utility class for string and byte array operations.
 *
 * @author ice4j
 */
public class StringUtils
{
    /**
     * Private constructor to prevent instantiation.
     */
    private StringUtils()
    {
    }

    /**
     * Converts byte array to hex string (all bytes).
     *
     * @param data the byte array
     * @return hex string (uppercase), or empty string if data is null
     */
    public static String formatBytesToHex(byte[] data)
    {
        return formatBytesToHex(data, -1);
    }

    /**
     * Converts byte array to hex string with optional limit.
     *
     * @param data the byte array
     * @param maxBytes max bytes to convert (<=0 means all)
     * @return hex string (uppercase), or empty string if data is null
     */
    public static String formatBytesToHex(byte[] data, int maxBytes)
    {
        if (data == null)
        {
            return "";
        }

        int len = (maxBytes > 0 && data.length > maxBytes) ? maxBytes : data.length;
        StringBuilder sb = new StringBuilder(len * 2);

        for (int i = 0; i < len; i++)
        {
            sb.append(String.format("%02X", data[i] & 0xFF));
        }

        if (maxBytes > 0 && data.length > maxBytes)
        {
            sb.append("...");
        }

        return sb.toString();
    }

    /**
     * Checks if byte array contains printable characters.
     * Considers bytes in range 32-126 (printable ASCII) as printable.
     * Also allows some common extended characters (>= 160).
     *
     * @param bytes the byte array to check
     * @return true if bytes represent printable text, false otherwise or if bytes is null
     */
    public static boolean isPrintable(byte[] bytes)
    {
        if (bytes == null)
        {
            return false;
        }

        for (byte b : bytes)
        {
            int value = b & 0xFF;
            // Check for printable ASCII range
            if (value < 32 || value > 126)
            {
                // Allow extended characters (>= 160)
                if (value < 160)
                {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Converts byte array to printable string.
     * If bytes are printable and length <= 128, returns the UTF-8 text.
     * Otherwise returns hex representation (first 16 bytes).
     *
     * @param bytes the byte array
     * @return printable string or hex representation
     */
    public static String bytesToPrintableString(byte[] bytes)
    {
        if (bytes == null)
        {
            return "";
        }

        // Try to decode as UTF-8 string
        try
        {
            if (isPrintable(bytes) && bytes.length <= 128)
            {
                return new String(bytes, "UTF-8");
            }
        }
        catch (Exception e)
        {
            // Fall through to hex representation
        }

        // Return hex representation (first 16 bytes)
        return formatBytesToHex(bytes, 16);
    }
}