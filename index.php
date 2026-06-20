<?php
require_once __DIR__ . '/includes/session.php';
require_once __DIR__ . '/includes/helpers.php';
SessionManager::start();

if (empty($_SESSION['uid'])) {
    redirect('/login.php');
}
redirect(($_SESSION['role'] ?? '') === 'admin' ? '/admin/dashboard.php' : '/dashboard.php');
