<?php

/**
 * "Continue with Google".
 *
 * The browser hands us an ID token that Google signed. Everything hinges on
 * verifying that token properly — an unverified token is just a string the
 * client made up, and trusting it would let anyone sign in as anyone.
 *
 * We check it with Google's tokeninfo endpoint, then re-check the claims
 * ourselves. In particular `aud` must be OUR client id: a token minted for a
 * different application is a perfectly valid Google token, and accepting it
 * would be a real vulnerability.
 */
class GoogleAuth
{
    private const TOKENINFO = 'https://oauth2.googleapis.com/tokeninfo?id_token=';

    private const ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

    /** Is Google sign-in switched on? It needs a client id to work. */
    public static function enabled(): bool
    {
        return self::clientId() !== '';
    }

    public static function clientId(): string
    {
        $config = require __DIR__ . '/../config/config.php';
        return trim($config['google']['client_id'] ?? '');
    }

    /**
     * Verify an ID token and return its claims.
     *
     * @return array{sub: string, email: string, name: string, picture: ?string}
     * @throws RuntimeException if the token is not one we should trust
     */
    public static function verify(string $idToken): array
    {
        if ($idToken === '') {
            throw new RuntimeException('No Google credential was supplied');
        }

        $claims = self::fetchClaims($idToken);

        // --- the checks that actually matter ---

        // 1. Was this token minted for US? Rejecting this is the whole ballgame.
        if (($claims['aud'] ?? '') !== self::clientId()) {
            throw new RuntimeException('That Google token was issued for a different application');
        }

        // 2. Did Google issue it?
        if (!in_array($claims['iss'] ?? '', self::ISSUERS, true)) {
            throw new RuntimeException('That token was not issued by Google');
        }

        // 3. Is it still alive? (tokeninfo enforces this, but never rely on that alone)
        if ((int) ($claims['exp'] ?? 0) < time()) {
            throw new RuntimeException('That Google sign-in has expired. Try again.');
        }

        // 4. Google itself must vouch for the address, or an attacker could
        //    register an unverified Gmail alias and inherit someone's account.
        $verified = $claims['email_verified'] ?? 'false';
        if ($verified !== true && $verified !== 'true') {
            throw new RuntimeException('That Google account has no verified email address');
        }

        if (empty($claims['sub']) || empty($claims['email'])) {
            throw new RuntimeException('Google did not return enough detail to sign you in');
        }

        return [
            'sub'     => (string) $claims['sub'],
            'email'   => strtolower((string) $claims['email']),
            'name'    => (string) ($claims['name'] ?? explode('@', $claims['email'])[0]),
            'picture' => $claims['picture'] ?? null,
        ];
    }

    /** Ask Google what this token says. */
    private static function fetchClaims(string $idToken): array
    {
        $curl = curl_init(self::TOKENINFO . urlencode($idToken));
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error = curl_error($curl);
        curl_close($curl);

        if ($body === false) {
            throw new RuntimeException("Could not reach Google to verify the sign-in ($error)");
        }
        if ($status !== 200) {
            throw new RuntimeException('Google rejected that sign-in token');
        }

        $claims = json_decode($body, true);
        if (!is_array($claims)) {
            throw new RuntimeException('Google returned something we could not read');
        }

        return $claims;
    }

    /**
     * Turn a verified Google identity into a username that is unique here.
     * "jane.doe@gmail.com" wants to be "jane_doe", but somebody may have it.
     */
    public static function suggestUsername(string $email): string
    {
        $base = strtolower(explode('@', $email)[0]);
        $base = preg_replace('/[^a-z0-9_]/', '_', $base);
        $base = trim(substr($base, 0, 30), '_') ?: 'user';

        $candidate = $base;
        $suffix = 1;

        while (Database::one('SELECT id FROM users WHERE username = ?', [$candidate])) {
            $candidate = $base . '_' . (++$suffix);
        }

        return $candidate;
    }
}
