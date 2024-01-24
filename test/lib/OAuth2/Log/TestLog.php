<?php

namespace OAuth2\Log;

use OAuth2\LogInterface;

class TestLog implements LogInterface
{
    public static function error(string $message, array $context = [])
    {
        return $message;
    }

    public static function info(string $message, array $context = [])
    {
        return $message;
    }
}