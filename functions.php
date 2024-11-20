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

function guard() {
    if (!isset($_SESSION['email']) || empty($_SESSION['email'])) {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $host = $_SERVER['HTTP_HOST'];
        $baseURL = $protocol . $host . '/'; 

        header("Location: " . $baseURL);
        exit();
    }
}

// Function to check for duplicate subject data or subject name in the database
function checkDuplicateSubject($subject_code, $subject_name) {
    $connection = database_connection();
    
    // Check for duplicate subject code
    $query = "SELECT * FROM subjects WHERE subject_code = ?";
    $stmt = $connection->prepare($query);
    $stmt->bind_param('s', $subject_code);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        return "Subject code already exists. Please choose another."; // Return the error message for duplicate code
    }
    
    // Check for duplicate subject name
    $query = "SELECT * FROM subjects WHERE subject_name = ?";
    $stmt = $connection->prepare($query);
    $stmt->bind_param('s', $subject_name);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        return "Subject name already exists. Please choose another."; // Return the error message for duplicate name
    }
    
    return ''; // No duplicate found
}


function displayErrors($errors) {
    if (empty($errors)) {
        return '';
    }
    $html = '<div class="alert alert-danger alert-dismissible fade show" role="alert">';
    $html .= '<strong>Validation Errors:</strong><ul>';
    foreach ($errors as $error) {
        $html .= '<li>' . htmlspecialchars($error) . '</li>';
    }
    $html .= '</ul>';
    $html .= '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
    $html .= '</div>';
    return $html;
}

function renderAlert($messages, $type = 'danger') {
    if (empty($messages)) {
        return '';
    }
    // Ensure messages is an array
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