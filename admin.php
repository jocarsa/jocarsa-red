<?php
session_start();

// Define the path to the SQLite database (shared with the security log).
$db_file = __DIR__ . '/attack_log.sqlite';

try {
    $pdo = new PDO('sqlite:' . $db_file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Create the attacks table if not exists.
$pdo->exec("CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    source TEXT,
    value TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Create the users table if not exists.
$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    name TEXT,
    email TEXT
)");

// Create the whitelist table if not exists.
$pdo->exec("CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE
)");

// Insert default user if no users exist.
$stmt = $pdo->query("SELECT COUNT(*) FROM users");
if ($stmt->fetchColumn() == 0) {
    $default_password = password_hash("jocarsa", PASSWORD_DEFAULT);
    $stmtInsert = $pdo->prepare("INSERT INTO users (username, password, name, email) VALUES (:username, :password, :name, :email)");
    $stmtInsert->execute([
        ':username' => 'jocarsa',
        ':password' => $default_password,
        ':name'     => 'Jose Vicente Carratala',
        ':email'    => 'info@josevicentecarratala.com'
    ]);
}

// Process logout.
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Process login if not authenticated.
if (!isset($_SESSION['user'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user'] = $user;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $login_error = "Invalid credentials.";
        }
    }
    // Show login form if not authenticated.
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f1f1f1; display: flex; justify-content: center; align-items: center; height: 100vh; }
            form { background: #fff; padding: 20px; border: 1px solid #ccc; width: 300px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0; }
            input[type="submit"] { padding: 8px 12px; background: #0085ba; color: #fff; border: none; cursor: pointer; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <form method="post">
            <h2>Login</h2>
            <?php if (isset($login_error)) echo '<p class="error">'.$login_error.'</p>'; ?>
            <label>Username</label>
            <input type="text" name="username" required>
            <label>Password</label>
            <input type="password" name="password" required>
            <input type="submit" name="login" value="Login">
        </form>
    </body>
    </html>
    <?php
    exit;
}

// Handle CRUD actions.
$page = $_GET['page'] ?? 'dashboard';
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    if ($action === 'delete_attack' && isset($_GET['id'])) {
        $stmt = $pdo->prepare("DELETE FROM attacks WHERE id = :id");
        $stmt->execute([':id' => $_GET['id']]);
        header("Location: ?page=attacks");
        exit;
    }
    if ($action === 'delete_user' && isset($_GET['id'])) {
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
        $stmt->execute([':id' => $_GET['id']]);
        header("Location: ?page=users");
        exit;
    }
    if ($action === 'add_user' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password, name, email) VALUES (:username, :password, :name, :email)");
        try {
            $stmt->execute([
                ':username' => $username,
                ':password' => $password_hash,
                ':name'     => $name,
                ':email'    => $email
            ]);
            header("Location: ?page=users");
            exit;
        } catch (PDOException $e) {
            $user_error = "Error: " . $e->getMessage();
        }
    }
    if ($action === 'edit_user' && isset($_GET['id']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $id = $_GET['id'];
        $username = trim($_POST['username'] ?? '');
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        if (!empty($_POST['password'])) {
            $password_hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET username = :username, name = :name, email = :email, password = :password WHERE id = :id");
            $stmt->execute([
                ':username' => $username,
                ':name'     => $name,
                ':email'    => $email,
                ':password' => $password_hash,
                ':id'       => $id
            ]);
        } else {
            $stmt = $pdo->prepare("UPDATE users SET username = :username, name = :name, email = :email WHERE id = :id");
            $stmt->execute([
                ':username' => $username,
                ':name'     => $name,
                ':email'    => $email,
                ':id'       => $id
            ]);
        }
        header("Location: ?page=users");
        exit;
    }
    if ($action === 'add_whitelist' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $ip = trim($_POST['ip'] ?? '');
        $stmt = $pdo->prepare("INSERT INTO whitelist (ip) VALUES (:ip)");
        try {
            $stmt->execute([':ip' => $ip]);
            header("Location: ?page=whitelist");
            exit;
        } catch (PDOException $e) {
            $whitelist_error = "Error: " . $e->getMessage();
        }
    }
    if ($action === 'delete_whitelist' && isset($_GET['id'])) {
        $stmt = $pdo->prepare("DELETE FROM whitelist WHERE id = :id");
        $stmt->execute([':id' => $_GET['id']]);
        header("Location: ?page=whitelist");
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Admin Panel</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #f1f1f1; }
    header { background: #23282d; color: #fff; padding: 10px; position: relative; }
    header h1 { margin: 0; font-size: 1.5em; }
    header .logout { position: absolute; right: 10px; top: 10px; }
    .container { display: flex; }
    nav { background: #32373c; color: #fff; width: 200px; min-height: calc(100vh - 50px); padding: 10px; }
    nav a { color: #fff; display: block; padding: 10px; text-decoration: none; }
    nav a:hover { background: #464b50; }
    .main { flex: 1; padding: 20px; background: #fff; min-height: calc(100vh - 50px); }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    table th, table td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    .button { background: #0085ba; color: #fff; padding: 6px 12px; text-decoration: none; border-radius: 3px; }
    .button:hover { background: #006799; }
    form { background: #fff; padding: 20px; border: 1px solid #ccc; }
    label { display: block; margin-top: 10px; }
    input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 8px; }
    input[type="submit"] { margin-top: 10px; padding: 8px 12px; background: #0085ba; color: #fff; border: none; border-radius: 3px; cursor: pointer; }
  </style>
</head>
<body>
  <header>
    <h1>Admin Panel</h1>
    <div class="logout"><a style="color:#fff;" href="?logout=1">Logout</a></div>
  </header>
  <div class="container">
    <nav>
      <a href="?page=dashboard">Dashboard</a>
      <a href="?page=attacks">Attack Attempts</a>
      <a href="?page=users">Users</a>
      <a href="?page=whitelist">Whitelist</a>
    </nav>
    <div class="main">
      <?php
      // Render content based on the current page.
      switch ($page) {
          case 'dashboard':
              $attackCount = $pdo->query("SELECT COUNT(*) FROM attacks")->fetchColumn();
              $userCount   = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
              $whitelistCount = $pdo->query("SELECT COUNT(*) FROM whitelist")->fetchColumn();
              echo "<h2>Dashboard</h2>";
              echo "<p>Total Attack Attempts: <strong>$attackCount</strong></p>";
              echo "<p>Total Users: <strong>$userCount</strong></p>";
              echo "<p>Total Whitelisted IPs: <strong>$whitelistCount</strong></p>";
              break;
          case 'attacks':
              echo "<h2>Attack Attempts</h2>";
              echo '<table>';
              echo '<tr><th>ID</th><th>IP</th><th>Source</th><th>Value</th><th>Timestamp</th><th>Actions</th></tr>';
              $stmt = $pdo->query("SELECT * FROM attacks ORDER BY timestamp DESC");
              while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                  echo "<tr>";
                  echo "<td>".$row['id']."</td>";
                  echo "<td>".$row['ip']."</td>";
                  echo "<td>".$row['source']."</td>";
                  echo "<td><pre>".htmlspecialchars($row['value'])."</pre></td>";
                  echo "<td>".$row['timestamp']."</td>";
                  echo "<td><a class='button' href='?action=delete_attack&id=".$row['id']."' onclick='return confirm(\"Delete this record?\")'>Delete</a></td>";
                  echo "</tr>";
              }
              echo '</table>';
              break;
          case 'users':
              echo "<h2>Users</h2>";
              echo '<a class="button" href="?page=add_user">Add New User</a><br><br>';
              echo '<table>';
              echo '<tr><th>ID</th><th>Username</th><th>Name</th><th>Email</th><th>Actions</th></tr>';
              $stmt = $pdo->query("SELECT * FROM users ORDER BY id ASC");
              while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                  echo "<tr>";
                  echo "<td>".$row['id']."</td>";
                  echo "<td>".$row['username']."</td>";
                  echo "<td>".$row['name']."</td>";
                  echo "<td>".$row['email']."</td>";
                  echo "<td>
                        <a class='button' href='?page=edit_user&id=".$row['id']."'>Edit</a>
                        <a class='button' href='?action=delete_user&id=".$row['id']."' onclick='return confirm(\"Delete this user?\")'>Delete</a>
                        </td>";
                  echo "</tr>";
              }
              echo '</table>';
              break;
          case 'add_user':
              echo "<h2>Add New User</h2>";
              if (isset($user_error)) {
                  echo "<p style='color:red;'>$user_error</p>";
              }
              ?>
              <form method="post" action="?action=add_user">
                  <label>Username</label>
                  <input type="text" name="username" required>
                  <label>Name</label>
                  <input type="text" name="name" required>
                  <label>Email</label>
                  <input type="email" name="email" required>
                  <label>Password</label>
                  <input type="password" name="password" required>
                  <input type="submit" value="Add User">
              </form>
              <?php
              break;
          case 'edit_user':
              if (isset($_GET['id'])) {
                  $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
                  $stmt->execute([':id' => $_GET['id']]);
                  $user = $stmt->fetch(PDO::FETCH_ASSOC);
                  if ($user) {
                      ?>
                      <h2>Edit User</h2>
                      <form method="post" action="?action=edit_user&id=<?php echo $user['id']; ?>">
                          <label>Username</label>
                          <input type="text" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
                          <label>Name</label>
                          <input type="text" name="name" value="<?php echo htmlspecialchars($user['name']); ?>" required>
                          <label>Email</label>
                          <input type="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                          <label>Password (leave blank to keep current)</label>
                          <input type="password" name="password">
                          <input type="submit" value="Update User">
                      </form>
                      <?php
                  } else {
                      echo "<p>User not found.</p>";
                  }
              }
              break;
          case 'whitelist':
              echo "<h2>Whitelist</h2>";
              echo '<a class="button" href="?page=add_whitelist">Add New IP</a><br><br>';
              echo '<table>';
              echo '<tr><th>ID</th><th>IP</th><th>Actions</th></tr>';
              $stmt = $pdo->query("SELECT * FROM whitelist ORDER BY id ASC");
              while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                  echo "<tr>";
                  echo "<td>".$row['id']."</td>";
                  echo "<td>".$row['ip']."</td>";
                  echo "<td>
                        <a class='button' href='?action=delete_whitelist&id=".$row['id']."' onclick='return confirm(\"Delete this IP?\")'>Delete</a>
                        </td>";
                  echo "</tr>";
              }
              echo '</table>';
              break;
          case 'add_whitelist':
              echo "<h2>Add New IP to Whitelist</h2>";
              if (isset($whitelist_error)) {
                  echo "<p style='color:red;'>$whitelist_error</p>";
              }
              ?>
              <form method="post" action="?action=add_whitelist">
                  <label>IP Address</label>
                  <input type="text" name="ip" required>
                  <input type="submit" value="Add IP">
              </form>
              <?php
              break;
          default:
              echo "<h2>Dashboard</h2>";
              break;
      }
      ?>
    </div>
  </div>
</body>
</html>

