<?php

/**
 * Local enrolment verification for RFC 6238 (SHA-1, six digits, 30 seconds).
 * Stalwart verifies the current password and existing OTP on every change.
 */
class rcube_stalwart_totp
{
    public static function secret()
    {
        $bits = '';
        foreach (unpack('C*', random_bytes(20)) as $byte) {
            $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
        }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        foreach (str_split($bits, 5) as $part) {
            $secret .= $alphabet[bindec($part)];
        }
        return $secret;
    }

    public static function uri($secret, $issuer, $account)
    {
        $issuer = str_replace(':', '', $issuer);
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account) . '?' . http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public static function verify($secret, $code, $time = null)
    {
        if (!is_string($secret) || !preg_match('/^[A-Z2-7]{32}$/D', $secret)
            || !is_string($code) || !preg_match('/^[0-9]{6}$/D', $code)
        ) {
            return false;
        }

        $bits = '';
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        foreach (str_split($secret) as $char) {
            $bits .= str_pad(decbin(strpos($alphabet, $char)), 5, '0', STR_PAD_LEFT);
        }
        $key = '';
        foreach (str_split($bits, 8) as $part) {
            $key .= chr(bindec($part));
        }

        $counter = intdiv($time ?? time(), 30);
        for ($step = max(0, $counter - 1); $step <= $counter + 1; $step++) {
            $hash = hash_hmac('sha1', pack('N2', intdiv($step, 4294967296), $step % 4294967296), $key, true);
            $offset = ord(substr($hash, -1)) & 15;
            $value = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;
            if (hash_equals(str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT), $code)) {
                return true;
            }
        }
        return false;
    }
}
