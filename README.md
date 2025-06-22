# ITS OneLogin Auth for WordPress

**Version:** 2.2.0  
**Author:** Umoor Dakheliyah, Colombo

Integrates the ITS OneLogin authentication system with WordPress, providing secure user authentication via ITS52 OAuth services. Securely processes user data fields returned from ITS52 and stores them encrypted in session and browser storage. Features include configurable endpoints, secure data encryption, and seamless user verification. Ideal for organizations seeking to implement single sign-on capabilities while maintaining security and compliance.

## Features

- **Secure Authentication**: Integrates with ITS52 for robust user authentication.
- **Data Encryption**: Encrypts user data (ITS No, Name, Gender, etc.) in the session and cookies using AES-128-CBC.
- **Configurable Settings**: An admin page to easily configure the auth endpoint, ITS app token, and app code.
- **Sitewide Protection**: Automatically checks for authentication on every page load and redirects to login if necessary.
- **Admin Bypass**: Logged-in WordPress administrators can bypass the ITS authentication.
- **Secure Callbacks**: Validates the referrer to ensure authentication requests are coming from trusted domains.
- **Persistent Login**: Uses cookies to maintain user sessions across browser restarts.
- **Debug Mode**: Includes a debug mode for easier troubleshooting.

## Installation

1.  **Zip the Plugin**: Create a `.zip` file of the `its-login-wordpress` directory.
2.  **Upload to WordPress**: In your WordPress admin dashboard, go to `Plugins` > `Add New` > `Upload Plugin`.
3.  **Install and Activate**: Upload the `.zip` file, install it, and then activate the plugin.

## Configuration

1.  **Set Salt Value**: Open `index.php` and replace `'ADD_THE_SALT_VALUE_HERE'` in the `ONLGN_SALT` definition with a unique, secret key. This is critical for securing encrypted data.

    ```php
    define('ONLGN_SALT', 'YOUR_SALT_KEY_HERE');
    ```

2.  **Configure Settings**: Go to `Settings` > `ITS OneLogin` in the WordPress admin area.
    -   **Auth Endpoint**: The URL slug for the authentication callback (default: `auth-ITS`).
    -   **ITS52 App Token**: The token for your application from ITS.
    -   **ITS52 App Code**: The application code from ITS.

3.  **Flush Rewrite Rules**: After saving your settings, go to `Settings` > `Permalinks` and click `Save Changes`. This ensures that your custom auth endpoint works correctly.

## How It Works

When an unauthenticated user visits the site, they are redirected to the ITS52 login page. After a successful login, ITS52 redirects them back to the configured auth endpoint with an encrypted data payload. The plugin decrypts this payload using **AES-128-CBC**. The decryption key is derived from the **ITS52 App Token** and the **ONLGN_SALT** value using PBKDF2. Once decrypted, the plugin verifies the user's details, establishes an authenticated session, and redirects the user to their original destination on the site.

## Accessing User Data

Once a user is authenticated, their data is stored in the PHP session and in browser cookies in an encrypted format. You can use the helper functions included in the plugin to securely access this data in your theme or other plugins.

-   `get_user_data('its_no')`: Returns the user's ITS number.
-   `get_user_data('its_name')`: Returns the user's name.
-   `get_user_data('its_gender')`: Returns the user's gender.
-   `get_user_data('its_age')`: Returns the user's age.
-   `get_user_data('its_city')`: Returns the user's city.
-   `get_user_data('its_jamiat')`: Returns the user's jamiat.
-   `get_user_data('its_user_data', '', true)`: Returns a PHP object with all user data.

Example usage in a WordPress template:

```php
if (function_exists('get_user_data')) {
    $userName = get_user_data('its_name');
    if ($userName) {
        echo "Welcome, " . esc_html($userName);
    }
}
```

### Core Helper Functions

For more advanced use cases, you can directly use the core helper functions provided by the plugin.

#### `get_user_data()`

This is the primary function for retrieving a specific piece of user data from the session or cookies. It automatically handles decrypting the value.

**Function Signature:**
`get_user_data($key, $default = '', $json_decode = false)`

-   `$key` (string): The key of the data to retrieve (e.g., `'its_no'`, `'its_name'`).
-   `$default` (mixed): The value to return if the key is not found.
-   `$json_decode` (bool): Set to `true` if the expected data is a JSON object or array.

**Example:**
```php
// Get the user's city, or return 'N/A' if not found
$city = get_user_data('its_city', 'N/A');
```

#### `decrypt()`

This function handles the decryption of a value that was encrypted by the plugin's internal `encrypt()` function. It uses **AES-256-CBC** and a secure key stored in the WordPress database. Note that this is different from the initial payload decryption from ITS52.

**Function Signature:**
`decrypt($encrypted, $json_decode = false)`

-   `$encrypted` (string): The base64-encoded encrypted string to decrypt.
-   `$json_decode` (bool): Set to `true` to automatically `json_decode` the decrypted string.

**Example:**
```php
// This is typically not called directly, as get_user_data handles it.
// But for demonstration, here's how you might use it:

if (isset($_COOKIE['its_user_data'])) {
    $encrypted_data = $_COOKIE['its_user_data'];
    $user_data_array = decrypt($encrypted_data, true); // Set to true to get an array

    if ($user_data_array) {
        echo 'Welcome, ' . esc_html($user_data_array['name']);
    }
}
```