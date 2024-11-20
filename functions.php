<?php 

function validate_and_login_user($email, $password) {
    $connection = database_connection();
    $password_hash = md5($password);

    $query = "SELECT * FROM users WHERE email = ? AND password = ?";
    $stmt = $connection->prepare($query);
    $stmt->bind_param('ss', $email, $password_hash);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['name'] = $user['name'];
        $_SESSION['email'] = $user['email'];
        return $user;
    }

    return false;
}


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

function render_alerts($messages, $type = 'danger') {
    if (empty($messages)) {
        return '';
    }
    
    if (!is_array($messages)) {
        $messages = [$messages];
    }

    $html = '<div class="alert alert-' . $type . ' alert-dismissible fade show" role="alert">';
    $html .= '<ul>';
    foreach ($messages as $message) {
        $html .= '<li>' . htmlspecialchars($message) . '</li>';
    }
    $html .= '</ul>';
    $html .= '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
    $html .= '</div>';

    return $html;
}

?>