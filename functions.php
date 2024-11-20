<?php 

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function database_connection() {
    $db_config = [
        'host' => 'localhost',
        'user' => 'root',
        'password' => '',
        'database' => 'dct-ccs-finals'
    ];

    $connection = new mysqli(
        $db_config['host'], 
        $db_config['user'], 
        $db_config['password'], 
        $db_config['database']
    );

    if ($connection->connect_error) {
        error_log("Connection failed: " . $connection->connect_error, 3, '/var/log/db_errors.log');
        return null;
    }

    return $connection;
}
?>