<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/helpers.php';
Auth::logout();
redirect('/login.php?msg=logout');
