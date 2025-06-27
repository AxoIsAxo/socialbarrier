package main

import (
	"database/sql" // Go's standard database interface
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver (underscore import for side effects)
	"golang.org/x/crypto/bcrypt"
)

// Post represents a single post entry (used for display)
type Post struct {
	Username string
	Content  string
	// ID int64 // Optional: could add ID if needed for display/ordering
}

// Global variable for our database connection
var db *sql.DB

// Define HTML templates directly in the Go code for simplicity
const indexHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Simple Go Web App Posts</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        .post { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }
        .post strong { color: #333; }
        form { margin-top: 20px; border: 1px solid #eee; padding: 15px; }
        input[type="text"], textarea, input[type="password"] { display: block; margin-bottom: 10px; width: 95%; padding: 8px; }
        input[type="submit"] { padding: 10px 15px; background-color: #007bff; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .lock-link { margin-top: 10px; display: inline-block; }
    </style>
</head>
<body>
    <h1>Posts</h1>

    {{if .}}
        {{range .}}
            <div class="post">
                <strong>{{.Username}}:</strong> {{.Content}}
            </div>
        {{end}}
    {{else}}
        <p>No posts yet.</p>
    {{end}}

    <h2>Add a New Post</h2>
    <form action="/post" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Password (only needed if username is locked):</label>
        <input type="password" id="password" name="password">

        <label for="content">Post Content:</label>
        <textarea id="content" name="content" rows="4" required></textarea>

        <input type="submit" value="Post">
    </form>

    <p class="lock-link"><a href="/lock">Lock a Username</a></p>

</body>
</html>
`

const lockHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Lock Username</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        form { margin-top: 20px; border: 1px solid #eee; padding: 15px; }
        input[type="text"], input[type="password"] { display: block; margin-bottom: 10px; width: 95%; padding: 8px; }
        input[type="submit"] { padding: 10px 15px; background-color: #007bff; color: white; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .back-link { margin-top: 10px; display: inline-block; }
    </style>
</head>
<body>
    <h1>Lock a Username</h1>

    <p>This will prevent anyone else from posting under this username without the password.</p>
    <p><strong>Warning:</strong> There is no way to recover or change the password.</p>

    <form action="/lock" method="post">
        <label for="username">Username to Lock:</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Set Password:</label>
        <input type="password" id="password" name="password" required>

        <input type="submit" value="Lock Username">
    </form>

    <p class="back-link"><a href="/">Back to Posts</a></p>

</body>
</html>
`

// initDB sets up the SQLite database and creates tables if they don't exist.
func initDB() error {
	// Open the database file. If it doesn't exist, it will be created.
	// Use the "file::memory:?cache=shared" data source name to use an in-memory database
	// for testing, but for persistence, provide a file path like "./socialbarrier.db".
	var err error
	db, err = sql.Open("sqlite3", "./socialbarrier.db") // Use a file path for persistence
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Check if the connection is valid
	err = db.Ping()
	if err != nil {
		db.Close() // Close if ping fails
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create the 'posts' table if it doesn't exist
	createPostsTableSQL := `CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		content TEXT NOT NULL
	);`
	_, err = db.Exec(createPostsTableSQL)
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create posts table: %w", err)
	}

	// Create the 'locked_users' table if it doesn't exist
	createLockedUsersTableSQL := `CREATE TABLE IF NOT EXISTS locked_users (
		username TEXT PRIMARY KEY UNIQUE,
		hashed_password BLOB NOT NULL
	);`
	_, err = db.Exec(createLockedUsersTableSQL)
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create locked_users table: %w", err)
	}

	log.Println("Database initialized successfully.")
	return nil
}

// indexHandler displays the existing posts.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Query all posts from the database
	rows, err := db.Query("SELECT username, content FROM posts ORDER BY id DESC") // Order by ID descending to show latest first
	if err != nil {
		http.Error(w, "Internal Server Error: Could not retrieve posts", http.StatusInternalServerError)
		log.Printf("Error querying posts: %v", err)
		return
	}
	defer rows.Close() // Always close rows when done

	posts := []Post{}
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.Username, &p.Content); err != nil {
			http.Error(w, "Internal Server Error: Could not read posts", http.StatusInternalServerError)
			log.Printf("Error scanning post row: %v", err)
			return
		}
		posts = append(posts, p)
	}

	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		http.Error(w, "Internal Server Error: Error during post iteration", http.StatusInternalServerError)
		log.Printf("Error after iterating through post rows: %v", err)
		return
	}

	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		http.Error(w, "Internal Server Error: Could not parse template", http.StatusInternalServerError)
		log.Printf("Error parsing index template: %v", err)
		return
	}

	err = tmpl.Execute(w, posts)
	if err != nil {
		http.Error(w, "Internal Server Error: Could not render template", http.StatusInternalServerError)
		log.Printf("Error executing index template: %v", err)
	}
}

// postHandler handles the submission of the new post form (POST requests).
func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request: Could not parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	content := r.FormValue("content")
	password := r.FormValue("password")

	if username == "" || content == "" {
		http.Error(w, "Bad Request: Username and content cannot be empty", http.StatusBadRequest)
		return
	}

	// Check if the username is locked
	var hashedPassword []byte
	// Query the locked_users table for the username
	err = db.QueryRow("SELECT hashed_password FROM locked_users WHERE username = ?", username).Scan(&hashedPassword)

	// Check the result of the query
	switch {
	case err == sql.ErrNoRows:
		// Username is not locked, proceed with adding the post
		log.Printf("Username '%s' is not locked.", username)
	case err != nil:
		// Some other database error occurred
		http.Error(w, "Internal Server Error: Database query failed", http.StatusInternalServerError)
		log.Printf("Error querying locked user '%s': %v", username, err)
		return
	default:
		// Username is locked, hashedPassword contains the hash
		log.Printf("Username '%s' is locked. Checking password.", username)
		if password == "" {
			http.Error(w, fmt.Sprintf("Unauthorized: Username '%s' is locked. Password is required.", username), http.StatusUnauthorized)
			return
		}
		err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
		if err != nil {
			log.Printf("Password comparison failed for user '%s': %v", username, err)
			http.Error(w, "Unauthorized: Incorrect password for this username.", http.StatusUnauthorized)
			return
		}
		// Password is correct, proceed to add the post
		log.Printf("Password correct for '%s'. Adding post.", username)
	}

	// Insert the new post into the database
	_, err = db.Exec("INSERT INTO posts (username, content) VALUES (?, ?)", username, content)
	if err != nil {
		http.Error(w, "Internal Server Error: Could not save post", http.StatusInternalServerError)
		log.Printf("Error inserting post: %v", err)
		return
	}

	// Redirect back to the home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// lockHandlerCombined handles both GET (display form) and POST (process form) for the /lock path.
func lockHandlerCombined(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Handle GET request: display the lock form
		tmpl, err := template.New("lock").Parse(lockHTML)
		if err != nil {
			http.Error(w, "Internal Server Error: Could not parse template", http.StatusInternalServerError)
			log.Printf("Error parsing lock template: %v", err)
			return
		}
		err = tmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, "Internal Server Error: Could not render template", http.StatusInternalServerError)
			log.Printf("Error executing lock template: %v", err)
		}

	case http.MethodPost:
		// Handle POST request: process the lock form submission
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad Request: Could not parse form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Bad Request: Username and password cannot be empty", http.StatusBadRequest)
			return
		}

		// --- NEW CHECK: See if the username is already locked ---
		var existingUsername string
		// Try to select the username from the locked_users table
		err = db.QueryRow("SELECT username FROM locked_users WHERE username = ?", username).Scan(&existingUsername)

		switch {
		case err == sql.ErrNoRows:
			// Good! Username is not locked. Proceed to hash and insert.
			log.Printf("Username '%s' is not locked. Proceeding to lock.", username)

			// Hash the password securely
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Internal Server Error: Could not process password", http.StatusInternalServerError)
				log.Printf("Error hashing password for user '%s': %v", username, err)
				return
			}

			// Insert the username and hashed password into the locked_users table.
			// Now we use a simple INSERT, not INSERT OR REPLACE.
			_, err = db.Exec("INSERT INTO locked_users (username, hashed_password) VALUES (?, ?)", username, hashedPassword)
			if err != nil {
				// This could happen if somehow another request locked it between the SELECT and INSERT
				http.Error(w, "Internal Server Error: Could not lock username (possible conflict)", http.StatusInternalServerError)
				log.Printf("Error inserting locked user '%s': %v", username, err)
				return
			}

			log.Printf("Username '%s' locked successfully.", username)
			// Redirect back to the home page
			http.Redirect(w, r, "/", http.StatusSeeOther)

		case err != nil:
			// Some other database error occurred during the check
			http.Error(w, "Internal Server Error: Database query failed during lock check", http.StatusInternalServerError)
			log.Printf("Error checking if user '%s' is locked: %v", username, err)

		default:
			// Username IS already locked (err was nil and Scan succeeded)
			log.Printf("Attempted to lock username '%s' which is already locked.", username)
			http.Error(w, fmt.Sprintf("Conflict: Username '%s' is already locked by someone else.", username), http.StatusConflict)
		}

	default:
		// Handle any other HTTP methods
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	// Initialize the database
	err := initDB()
	if err != nil {
		log.Fatal("Failed to initialize database: ", err)
	}
	// Ensure the database connection is closed when the program exits
	defer db.Close()

	// Register handlers
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/lock", lockHandlerCombined)

	// Start the HTTP server
	fmt.Println("Server starting on :8080...")
	err = http.ListenAndServe(":8080", nil) // Listen on port 8080
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
