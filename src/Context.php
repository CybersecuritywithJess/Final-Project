<?php

/**
 * The device / location fingerprint of the request that is being audited.
 *
 * Country and city would normally come from a GeoIP lookup. This is a demo
 * bank, so the client may declare them with X-Demo-Country / X-Demo-City —
 * that is what makes "login from another country" demonstrable without
 * actually flying anywhere.
 */
class Context
{
    public string $ip;
    public string $browser;
    public string $os;
    public string $deviceType;
    public string $country;
    public string $city;
    public string $fingerprint;
    public ?string $sessionId;

    public static function fromRequest(): self
    {
        $c = new self();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $c->browser = self::detectBrowser($ua);
        $c->os = self::detectOs($ua);
        $c->deviceType = self::detectDeviceType($ua);
        $c->ip = self::detectIp();
        $c->country = self::header('X-Demo-Country') ?: 'Kenya';
        $c->city = self::header('X-Demo-City') ?: 'Nairobi';
        $c->fingerprint = self::fingerprint($c->browser, $c->os, $c->deviceType);
        $c->sessionId = session_id() ?: null;

        return $c;
    }

    /** Stable id for a browser + OS + device-type combination. */
    public static function fingerprint(string $browser, string $os, string $deviceType): string
    {
        return substr(hash('sha256', "$browser|$os|$deviceType"), 0, 16);
    }

    private static function detectIp(): string
    {
        // A demo header wins, so an attack from "Russia" can be simulated.
        $demo = self::header('X-Demo-Ip');
        if ($demo) {
            return $demo;
        }

        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($forwarded !== '') {
            return trim(explode(',', $forwarded)[0]);
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        return $ip === '::1' ? '127.0.0.1' : $ip;
    }

    private static function detectBrowser(string $ua): string
    {
        // Order matters: Edge and Opera both claim to be Chrome.
        return match (true) {
            str_contains($ua, 'Edg/')                        => 'Edge',
            str_contains($ua, 'OPR/'), str_contains($ua, 'Opera') => 'Opera',
            str_contains($ua, 'Firefox')                     => 'Firefox',
            str_contains($ua, 'Chrome')                      => 'Chrome',
            str_contains($ua, 'Safari')                      => 'Safari',
            str_contains($ua, 'curl')                        => 'curl',
            default                                          => 'Unknown',
        };
    }

    private static function detectOs(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'Windows')  => 'Windows',
            str_contains($ua, 'Android')  => 'Android',
            str_contains($ua, 'iPhone'), str_contains($ua, 'iPad') => 'iOS',
            str_contains($ua, 'Mac OS')   => 'macOS',
            str_contains($ua, 'Linux')    => 'Linux',
            default                       => 'Unknown',
        };
    }

    private static function detectDeviceType(string $ua): string
    {
        return match (true) {
            str_contains($ua, 'iPad'), str_contains($ua, 'Tablet') => 'tablet',
            str_contains($ua, 'Mobile'), str_contains($ua, 'Android') => 'mobile',
            default => 'desktop',
        };
    }

    private static function header(string $name): ?string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        return $_SERVER[$key] ?? null;
    }
}
