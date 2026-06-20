<?php
/**
 * Misc utility helpers.
 */

function h(?string $s): string {
    return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $path): void {
    header("Location: $path");
    exit;
}

function security_headers(): void {
    // ---------- Remove server fingerprinting headers ----------
    // PHP can hide its own X-Powered-By header, removing one of the
    // information-disclosure findings reported by Nikto.
    header_remove('X-Powered-By');

    // ---------- Standard browser security headers ----------
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('X-XSS-Protection: 1; mode=block');

    // ---------- Content Security Policy ----------
    // - 'self' for own assets
    // - cdn.jsdelivr.net allowed for Chart.js (with the cross-domain trade-off
    //   accepted as documented in the scan-findings report)
    // - form-action and frame-ancestors declared explicitly so ZAP rule 10055
    //   ("CSP: Failure to Define Directive with No Fallback") is satisfied
    // - base-uri and object-src locked down to harden against tag-injection
    header("Content-Security-Policy: default-src 'self'; "
        . "script-src 'self' https://cdn.jsdelivr.net; "
        . "style-src 'self' 'unsafe-inline'; "
        . "font-src 'self' data:; "
        . "img-src 'self' data:; "
        . "connect-src 'self'; "
        . "form-action 'self'; "
        . "frame-ancestors 'none'; "
        . "base-uri 'self'; "
        . "object-src 'none';");

    // ---------- Permissions-Policy ----------
    // Disable browser features the app does not need. Closes the
    // "permissions-policy missing" finding from Nikto.
    header('Permissions-Policy: geolocation=(), camera=(), microphone=(), '
        . 'payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');

    // ---------- Strict-Transport-Security (HSTS) ----------
    // Hostinger terminates TLS at its proxy, so $_SERVER['HTTPS'] is not always
    // set even when the visitor is on HTTPS. Trust X-Forwarded-Proto too.
    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO']
        ?? ($_SERVER['HTTPS'] ?? '');
    if ($proto === 'https' || $proto === 'on' || !empty($_SERVER['HTTPS'])) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
}

function severity_color(string $sev): string {
    return [
        'info'     => '#3b82f6',
        'warning'  => '#f59e0b',
        'critical' => '#ef4444',
    ][$sev] ?? '#6b7280';
}

function status_badge(string $status): string {
    $map = [
        'active'       => ['#10b981', 'Active'],
        'locked'       => ['#f59e0b', 'Locked'],
        'disabled'     => ['#6b7280', 'Disabled'],
        'open'         => ['#ef4444', 'Open'],
        'acknowledged' => ['#f59e0b', 'Ack'],
        'resolved'     => ['#10b981', 'Resolved'],
    ];
    $m = $map[$status] ?? ['#6b7280', $status];
    return "<span class='badge' style='background:{$m[0]}20;color:{$m[0]};border:1px solid {$m[0]}40'>" . h($m[1]) . "</span>";
}

function relative_time(string $datetime): string {
    $diff = time() - strtotime($datetime);
    if ($diff < 60)    return "{$diff}s ago";
    if ($diff < 3600)  return floor($diff/60)."m ago";
    if ($diff < 86400) return floor($diff/3600)."h ago";
    if ($diff < 604800) return floor($diff/86400)."d ago";
    return date('M j', strtotime($datetime));
}
