# My Tiny Uploads Guard 🛡️

A lightweight, non-intrusive security guard for your WordPress uploads directory.

![Dashboard Preview](https://via.placeholder.com/800x400?text=My+Tiny+Uploads+Guard+Dashboard)  
*(Dashboard screenshot placeholder)*

## 📖 About (關於本專案)

My Tiny Uploads Guard is designed with two goals in mind:
1.  **Security**: Provide a simple, "set and forget" protection layer for the `wp-content/uploads` directory, which is often the target of malware injection.
2.  **Education**: Serve as a **"Living Textbook"** for WordPress developers. The codebase is heavily commented with "White-Talk" (plain language) explanations, covering security concepts, performance trade-offs, and PHP best practices.

## ✨ Key Features (核心功能)

*   **🔍 Async Smart Scanner**: Scans your uploads directory in small batches (AJAX-driven) to prevent server timeouts, even on shared hosting.
*   **🛡️ Defensive Triangle**: Dashboard provides instant visibility into your security status, monitored file count, and last scan time.
*   **🕵️‍♀️ Proxy-Aware Logging**: Logs both the direct IP and the `HTTP_X_FORWARDED_FOR` IP to detect attackers hiding behind proxies.
*   **🔒 Apache 2.4/2.2 Compatible**: Automatically secures its log directory with an `.htaccess` file compatible with both old and new Apache servers.
*   **🚀 "Tiny" Footprint**: No bloated database tables. scan results are transient, and stats are stored in simple `wp_options`.

## 🎓 Educational Value (程式碼裡的秘密)

We believe code should explain itself. Open `my-tiny-uploads-guard.php` or `includes/Scanner/Async_Key_Scanner.php` and you will find detailed comments explaining:

*   **Path Traversal Prevention**: Why `realpath()` is critical before deleting files.
*   **Race Conditions**: Why we use `LOCK_EX` when writing logs.
*   **Performance Complexity**: The O(N²) trade-off of using `RecursiveDirectoryIterator` with offsets, and why we chose it for simplicity.
*   **Error Suppression**: Proper usage of the `@` operator in PHP.

## 🛠️ Installation

1.  Download the ZIP file.
2.  Go to **Plugins > Add New > Upload Plugin**.
3.  Activate the plugin.
4.  Go to **My Tiny Uploads Guard** in the admin menu.
5.  Click **Start New Scan**.

## 🤝 Contribution

This is an open-source project. Feedback, Pull Requests, and Code Reviews are welcome!

## 📄 License

GPL-3.0 license.
