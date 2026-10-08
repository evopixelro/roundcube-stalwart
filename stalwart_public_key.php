<?php

/**
 * Reject private or unrelated key material before it is sent to the server.
 * The mail server performs the cryptographic public-key validation.
 */
class rcube_stalwart_public_key
{
    public static function validate($key)
    {
        if (!is_string($key) || strlen($key) > 16384) {
            throw new RuntimeException('invalidpublickey');
        }
        $key = trim(str_replace("\r\n", "\n", $key));
        if (stripos($key, 'PRIVATE KEY') !== false || stripos($key, 'SECRET KEY') !== false) {
            throw new RuntimeException('privatekeyrejected');
        }
        if (!preg_match('/\A-----BEGIN (PGP PUBLIC KEY BLOCK|CERTIFICATE)-----\n(.+)\n-----END \1-----\z/sD', $key, $matches)) {
            throw new RuntimeException('invalidpublickey');
        }
        if (strpos($matches[2], '-----') !== false) {
            throw new RuntimeException('invalidpublickey');
        }
        if ($matches[1] === 'CERTIFICATE') {
            if (!function_exists('openssl_x509_read') || !@openssl_x509_read($key)) {
                throw new RuntimeException('invalidpublickey');
            }
        }
        else {
            $body = preg_replace('/^(?:Version|Comment|Charset):[^\n]*\n/m', '', $matches[2]);
            $body = preg_replace('/^=[A-Za-z0-9+\/]{4}\s*$/m', '', $body);
            $data = base64_decode(preg_replace('/\s+/', '', $body), true);
            if ($data === false || $data === '') {
                throw new RuntimeException('invalidpublickey');
            }
            self::check_packets($data);
        }
        return $key . "\n";
    }

    /**
     * Inspect RFC 4880 packet headers; public armour alone is not a safety check.
     * Partial/indeterminate packets are deliberately rejected for imported keys.
     */
    private static function check_packets($data)
    {
        $offset = 0;
        $size = strlen($data);
        $has_public_key = false;
        while ($offset < $size) {
            $header = ord($data[$offset++]);
            if (!($header & 128)) {
                throw new RuntimeException('invalidpublickey');
            }
            $tag = ($header & 64) ? ($header & 63) : (($header >> 2) & 15);
            if ($tag === 5 || $tag === 7) {
                throw new RuntimeException('privatekeyrejected');
            }
            if (!in_array($tag, [2, 6, 13, 14, 17], true) || $offset >= $size) {
                throw new RuntimeException('invalidpublickey');
            }
            $has_public_key = $has_public_key || $tag === 6;
            if ($header & 64) {
                $first = ord($data[$offset++]);
                if ($first < 192) {
                    $length = $first;
                }
                else if ($first < 224 && $offset < $size) {
                    $length = (($first - 192) << 8) + ord($data[$offset++]) + 192;
                }
                else if ($first === 255 && $offset + 4 <= $size) {
                    $length = unpack('N', substr($data, $offset, 4))[1];
                    $offset += 4;
                }
                else {
                    throw new RuntimeException('invalidpublickey');
                }
            }
            else {
                $bytes = [1, 2, 4, 0][$header & 3];
                if (!$bytes || $offset + $bytes > $size) {
                    throw new RuntimeException('invalidpublickey');
                }
                $length = 0;
                for ($i = 0; $i < $bytes; $i++) {
                    $length = ($length << 8) | ord($data[$offset++]);
                }
            }
            if ($length <= 0 || $length > $size - $offset) {
                throw new RuntimeException('invalidpublickey');
            }
            $offset += $length;
        }
        if (!$has_public_key) {
            throw new RuntimeException('invalidpublickey');
        }
    }
}
