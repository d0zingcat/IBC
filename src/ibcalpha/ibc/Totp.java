// This file is part of IBC.
// Copyright (C) 2026 Goldmachine contributors
// For conditions of distribution and use, see copyright notice in COPYING.txt

// IBC is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ibcalpha.ibc;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238 six-digit TOTP generator using the JDK's HMAC-SHA1 implementation. */
final class Totp {
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Totp() {}

    static String generate(String secret) {
        return generate(secret, System.currentTimeMillis());
    }

    static String generate(String secret, long timestampMillis) {
        byte[] key = decode(secret);
        long counter = timestampMillis / 30_000L;
        byte[] message = ByteBuffer.allocate(8).putLong(counter).array();
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(message);
            int offset = hash[hash.length - 1] & 0x0f;
            int value = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format("%06d", value % 1_000_000);
        } catch (NoSuchAlgorithmException | InvalidKeyException error) {
            throw new RuntimeException("HMAC-SHA1 unavailable", error);
        }
    }

    private static byte[] decode(String input) {
        if (input == null) throw new IllegalArgumentException("empty Base32 TOTP secret");
        String encoded = input.toUpperCase().replaceAll("[=\\s]", "");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (int index = 0; index < encoded.length(); index++) {
            int value = BASE32.indexOf(encoded.charAt(index));
            if (value < 0) throw new IllegalArgumentException("invalid Base32 TOTP secret");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                output.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
                buffer &= (1 << bits) - 1;
            }
        }
        if (output.size() == 0) throw new IllegalArgumentException("empty Base32 TOTP secret");
        return output.toByteArray();
    }
}
