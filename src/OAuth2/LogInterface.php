<?php

namespace OAuth2;

/**
 * This interface is an abstraction for the used logging mechanism from your app
 */
interface LogInterface {
    public static function error(string $message, array $context = []);
    public static function info(string $message, array $context = []);
}