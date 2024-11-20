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


function handleEditSubject($subject_id) {
    $connection = database_connection();
    $query = "SELECT * FROM subjects WHERE id = ?";
    $stmt = $connection->prepare($query);
    $stmt->bind_param('i', $subject_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $subject = $result->fetch_assoc();

    if (!$subject) {
        return "Subject not found.";
    } else {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_subject'])) {
            $subject_name = trim($_POST['subject_name']);
            $subject_code = trim($_POST['subject_code']);

            if (empty($subject_name)) {
                return "Subject name cannot be empty.";
            } else {
                $duplicate_query = "SELECT * FROM subjects WHERE (subject_name = ? OR subject_code = ?) AND id != ?";
                $duplicate_stmt = $connection->prepare($duplicate_query);
                $duplicate_stmt->bind_param('ssi', $subject_name, $subject_code, $subject_id);
                $duplicate_stmt->execute();
                $duplicate_result = $duplicate_stmt->get_result();

                if ($duplicate_result->num_rows > 0) {
                    return "A subject with the same name or code already exists.";
                } else {
                    $update_query = "UPDATE subjects SET subject_name = ?, subject_code = ? WHERE id = ?";
                    $update_stmt = $connection->prepare($update_query);
                    $update_stmt->bind_param('ssi', $subject_name, $subject_code, $subject_id);

                    if ($update_stmt->execute()) {
                        header("Location: /admin/subjects/add.php?message=Subject+updated+successfully");
                        exit();
                    } else {
                        return "Failed to update the subject. Please try again.";
                    }
                }
            }
        }
    }

    return $subject;
}

function deleteSubject($subject_id) {
    $connection = database_connection();
    $query = "SELECT * FROM subjects WHERE id = ?";
    $stmt = $connection->prepare($query);
    $stmt->bind_param('i', $subject_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $subject = $result->fetch_assoc();

    if (!$subject) {
        return ["error" => "Subject not found."];
    } else {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_subject'])) {
            $delete_query = "DELETE FROM subjects WHERE id = ?";
            $delete_stmt = $connection->prepare($delete_query);
            $delete_stmt->bind_param('i', $subject_id);

            if ($delete_stmt->execute()) {
                header("Location: /admin/subjects/add.php");
                exit();
            } else {
                return ["error" => "Failed to delete the subject: " . $connection->error];
            }
        }
    }

    return ["subject" => $subject];
}


?>