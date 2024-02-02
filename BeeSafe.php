<?php
/*
Plugin Name: BeeSafe by pottr.io
Description: A plugin to track and display failed login attempts, block specific IP addresses using .htaccess, and set lockout durations. Sends data to an external API after failed login attempts. Displays latest WordPress CVEs.
Version: 1.0
Author URI: https://pottr.io/wordpress
Author: Christopher Ivie
License: GPL2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

*/
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', true);

define('ICON_URL', plugins_url('pottr-logo.svg', __FILE__));


register_activation_hook(__FILE__, 'login_attempt_tracker_create_table');

function login_attempt_tracker_create_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_attempts';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        username varchar(255) NOT NULL,
        ip_address varchar(45) NOT NULL,
        attempt_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        lockout_expires datetime DEFAULT NULL,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

add_action('wp_login_failed', 'login_attempt_tracker_failed_login');

function login_attempt_tracker_failed_login($username) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_attempts';
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $max_attempts = get_option('beesafe_settings')['beesafe_field_attempts'];
    $lockout_duration = get_option('beesafe_settings')['beesafe_field_timeout']; // Assuming timeout is stored in minutes

    // Check if the IP address is locked out
    $lockout_expires = $wpdb->get_var($wpdb->prepare(
        "SELECT lockout_expires FROM $table_name WHERE ip_address = %s",
        $ip_address
    ));

    if ($lockout_expires && current_time('mysql', 1) < $lockout_expires) {
        wp_die('Too many login attempts. Please try again later.');
    }

    // Inline preparation and execution to satisfy the plugin checker, even though it's less readable
    $recent_attempt = $wpdb->get_row($wpdb->prepare(
        "SELECT id, attempt_count, attempt_time FROM $table_name WHERE ip_address = %s AND username = %s ORDER BY attempt_time DESC LIMIT 1",
        $ip_address, $username
    ));
    $current_time = current_time('mysql', 1);
    if ($recent_attempt) {
        $time_diff = strtotime($current_time) - strtotime($recent_attempt->attempt_time);

        if ($time_diff < $lockout_duration * 60) { // Convert minutes to seconds
            if ($recent_attempt->attempt_count >= $max_attempts) {
                // Lock the IP address and set lockout_expires time
                $lockout_expires = gmdate('Y-m-d H:i:s', strtotime($current_time) + ($lockout_duration * 60));
                $wpdb->update(
                    $table_name,
                    ['lockout_expires' => $lockout_expires],
                    ['ip_address' => $ip_address],
                    ['%s'],
                    ['%s']
                );
                wp_die('Too many login attempts. Please try again later.');
            } else {
                $wpdb->update(
                    $table_name,
                    ['attempt_count' => $recent_attempt->attempt_count + 1, 'attempt_time' => $current_time],
                    ['id' => $recent_attempt->id],
                    ['%d', '%s'],
                    ['%d']
                );
            }
        } else {
            $wpdb->update(
                $table_name,
                ['attempt_count' => 1, 'attempt_time' => $current_time],
                ['id' => $recent_attempt->id],
                ['%d', '%s'],
                ['%d']
            );
        }
    } else {
        $wpdb->insert(
            $table_name,
            ['username' => $username, 'ip_address' => $ip_address, 'attempt_count' => 1, 'attempt_time' => $current_time],
            ['%s', '%s', '%d', '%s']
        );
    }
    send_login_attempt_to_api($username, $ip_address, current_time('mysql', 1));

}


function login_attempt_tracker_update_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_attempts';

    $row = $wpdb->get_results("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = '$table_name' AND column_name = 'attempt_count'");
  
    if(empty($row)){
       $wpdb->query("ALTER TABLE $table_name ADD attempt_count int(11) DEFAULT 0 NOT NULL");
    }
}

// Call this function at an appropriate place, such as plugin activation or initialization
login_attempt_tracker_update_table();


function send_login_attempt_to_api($username, $ip_address, $attempt_time) {
    $api_url = 'https://pottr.io/api/v2/wordpress.php';
    $api_key = '!!@@##';

    $body = [
        'api_key' => $api_key,
        'username' => $username,
        'ip_address' => $ip_address,
        'attempt_time' => $attempt_time,
    ];

    $args = [
        'method' => 'POST',
        'timeout' => 45,
        'redirection' => 5,
        'httpversion' => '1.0',
        'blocking' => true,
        'headers' => [],
        'body' => json_encode($body),
        'cookies' => [],
    ];

    $response = wp_remote_post($api_url, $args);

    if (is_wp_error($response)) {
        $error_message = $response->get_error_message();
    }
}

add_action('admin_head', 'custom_plugin_admin_styles');

function custom_plugin_admin_styles() {
    echo '<style>
        .menu-icon-my-plugin div.wp-menu-image { margin-top: 10px; }
        img.plugin-logo { max-width: 100%; height: auto; margin-top: 20px; }
        .plugin-description { margin: 20px 0; }
    </style>';
}

add_action('admin_menu', 'login_attempt_tracker_admin_menu');

function login_attempt_tracker_admin_menu() {
    $icon_url = plugins_url('pottr-logo.svg', __FILE__);
    add_menu_page(
        'Failed Login Attempts',
        'BeeSafe',
        'manage_options',
        'login-attempts',
        'login_attempt_tracker_display_admin_page',
        $icon_url,
        6
    );
}

function login_attempt_tracker_display_admin_page() {
    $icon_url = plugins_url('pottr-logo.svg', __FILE__);
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_attempts';

    if (isset($_GET['flush_login_attempts']) && current_user_can('manage_options')) {
        // Check if our nonce is set.
        if (isset($_GET['flush_login_attempts_nonce'])) {
            // Verify the nonce.
            $nonce = sanitize_text_field($_GET['flush_login_attempts_nonce']);
            if (!wp_verify_nonce($nonce, 'flush_login_attempts_action')) {
                // Nonce did not verify, handle the error.
                wp_die('Security check failed.');
            } else {
                global $wpdb;
                $table_name = $wpdb->prefix . 'login_attempts';

                // Ensuring the table name is safe by using it with known strings provided by $wpdb
                if ($table_name === $wpdb->prefix . 'login_attempts') {
                    $wpdb->query("DELETE FROM {$table_name}");
                } else {
                    // Handle unexpected table name
                    wp_die('An error occurred while trying to clear login attempts.');
                }
            }
        } else {
            // Nonce is not set.
            wp_die('Nonce field is missing. Security check failed.');
        }
    }
    

    if (isset($_GET['lockout_ip']) && current_user_can('manage_options')) {
        $ip_address = sanitize_text_field($_GET['lockout_ip']);
        $duration = isset($_GET['lockout_duration']) ? intval($_GET['lockout_duration']) : 60; // Default to 60 minutes if not set
        $error_message = login_attempt_tracker_set_lockout($ip_address, $duration);
        if ($error_message) {
            echo '<div class="notice notice-error"><p>' . esc_html($error_message) . '</p></div>';
        } else {
            echo '<div class="notice notice-success"><p>IP blocking rule updated successfully.</p></div>';
        }
    }

    echo '<div class="wrap"><img src="' . $icon_url . '" class="plugin-logo" style="height:150px; width: 150px;"/>'; 
    echo '<h2>BeeSafe Plugin by <a href="https://pottr.io" target="_blank">pottr.io</a></h2>';
    echo '<div class="plugin-description">';
    echo '<p>This plugin allows you to track and display failed login attempts, block specific IP addresses, and set lockout durations. It is powered by an open-source honeypot called pottr.io, which aims to protect the internet by using deception technologies.</p>';
    echo '</div>';

    $failed_attempts = $wpdb->get_results("SELECT * FROM $table_name ORDER BY attempt_time DESC");

    echo '<h2>Failed Login Attempts</h2>';
    echo '<table class="widefat">';
    echo '<thead><tr><th>Username</th><th>IP Address</th><th>Attempt Time</th><th>Lockout Actions</th></tr></thead>';
    echo '<tbody>';
    foreach ($failed_attempts as $attempt) {
        echo '<tr><td>' . esc_html($attempt->username) . '</td>';
        echo '<td>' . esc_html($attempt->ip_address) . '</td>';
        echo '<td>' . esc_html($attempt->attempt_time) . '</td>';
        echo '<td>';
        if (isset($attempt->lockout_expires) && current_time('mysql', 1) < $attempt->lockout_expires) {
            echo 'Locked until ' . esc_html($attempt->lockout_expires);
        } else {
            echo '<form action="" method="get">';
            echo '<input type="hidden" name="page" value="login-attempts" />';
            echo '<input type="hidden" name="lockout_ip" value="' . esc_attr($attempt->ip_address) . '" />';
            echo '<input type="number" name="lockout_duration" min="1" placeholder="Duration (minutes)" required />';
            echo '<input type="submit" value="Lockout IP" class="button button-secondary" />';
            echo '</form>';
        }
        echo '</td></tr>';
    }
    echo '</tbody></table>';

    echo '<form method="get">';
    echo '<input type="hidden" name="page" value="login-attempts" />';
    echo '<input type="hidden" name="flush_login_attempts" value="1" />';
    wp_nonce_field('flush_login_attempts_action', 'flush_login_attempts_nonce');
    echo '<input type="submit" value="Flush Login Attempts" class="button button-secondary" />';
    echo '</form>';

    display_cve_data();
}

function display_cve_data() {
    $cve_data = fetch_wordpress_cves();

    echo '<div class="wrap"><h2>Latest WordPress CVEs</h2>';
    if (is_array($cve_data) && count($cve_data) > 0) {
        echo '<table class="widefat"><thead><tr><th>ID</th><th>Severity</th><th>Description</th><th>Last Modified</th><th>Published Date</th></tr></thead><tbody>';
        foreach ($cve_data as $cve) {
            echo '<td><a href="https://pottr.io/live-cve/cve_detail.php?id=' . esc_attr($cve['id']) . '" target="_blank">' . esc_html($cve['id']) . '</a></td>';
            echo '<td>' . esc_html($cve['baseSeverity']) . '</td>';
            echo '<td>' . esc_html($cve['description']) . '</td>';
            echo '<td>' . esc_html($cve['lastModifiedDate']) . '</td>';
            echo '<td>' . esc_html($cve['publishedDate']) . '</td></tr>';

        }
        echo '</tbody></table>';
    } else {
        echo '<p>No CVE data found.</p>';
    }
    echo '</div>';
}

function fetch_wordpress_cves() {
    $api_url = 'https://pottr.io/live-cve/api.php?keyword=wordpress';
    $response = wp_remote_get($api_url);

    if (is_wp_error($response)) {
        return [];
    } else {
        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true); // Assuming the API returns an array of CVEs
    }
}

function login_attempt_tracker_set_lockout($ip_address, $duration) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_attempts';

    $lockout_expires = gmdate('Y-m-d H:i:s', strtotime(current_time('mysql', 1)) + ($duration * 60));

    $wpdb->update(
        $table_name,
        ['lockout_expires' => $lockout_expires],
        ['ip_address' => $ip_address],
        ['%s'],
        ['%s']
    );

    return update_htaccess_with_blocked_ip($ip_address, true);
}

function update_htaccess_with_blocked_ip($ip_address, $block = true) {
    require_once(ABSPATH . 'wp-admin/includes/file.php');
    WP_Filesystem();
    global $wp_filesystem;

    $htaccess_path = ABSPATH . '.htaccess'; 
    $lines = $wp_filesystem->get_contents_array($htaccess_path);

    if ($lines === false) {
        // Handle the error, e.g., log an error message
        $error_message = "Failed to open .htaccess file at {$htaccess_path}";
        error_log($error_message);
        return $error_message;
    }

    $rule = "Deny from $ip_address";

    if ($block) {
        if (!in_array($rule, $lines)) {
            array_unshift($lines, $rule);
        }
    } else {
        $key = array_search($rule, $lines);
        if ($key !== false) {
            unset($lines[$key]);
        }
    }

    // Check if .htaccess is writable
    if (!$wp_filesystem->is_writable($htaccess_path)) {
        $error_message = "Permission denied: .htaccess file is not writable";
        error_log($error_message);
        return $error_message;
    }

    $write_success = $wp_filesystem->put_contents($htaccess_path, implode("\n", $lines));

    if ($write_success) {
        // Log success message
        error_log("IP blocking rule updated successfully in .htaccess");
        return true;
    } else {
        // Log error message if write fails
        $error_message = "Failed to update .htaccess file at {$htaccess_path}";
        error_log($error_message);
        return $error_message;
    }
}


function isHtaccessActive() {
    $htaccess_path = ABSPATH . '.htaccess'; 

    if (file_exists($htaccess_path) && is_readable($htaccess_path)) {
        return true;
    }

    return false; // .htaccess file does not exist or is not readable
}


function displayHtaccessStatus() {
    $isActive = isHtaccessActive();

    if ($isActive) {
        echo '<div class="notice notice-success"><p>.htaccess is active and in use.</p></div>';
    } else {
        echo '<div class="notice notice-warning"><p>.htaccess is not active or not accessible. Please check your server configuration.</p></div>';
    }
}

// Add the status message to plugin page
add_action('admin_notices', 'displayHtaccessStatus');


add_filter('login_errors', 'customize_login_error_message');

function customize_login_error_message($error) {
    // Check if the error message contains the specific text indicating a non-existent username
    if (strpos($error, 'not registered on this site') !== false) {
        // Replace the default message with your custom message
        $error = 'Login failed, this website is protected by <a href="https://pottr.io/wordpress" target="_blank">pottr.io/wordpress. </a> Please contact your administrator.' ;
    }

    return $error;
}

add_action('admin_menu', 'beesafe_add_admin_menu');

function beesafe_add_admin_menu() {
    add_options_page(
        'BeeSafe Settings',
        'BeeSafe Settings',
        'manage_options',
        'beesafe-settings',
        'beesafe_settings_page'
    );
}

add_action('admin_init', 'beesafe_settings_init');

function beesafe_settings_init() {
    register_setting('beesafe', 'beesafe_settings');

    add_settings_section(
        'beesafe_section',
        __('Your section description', 'beesafe'),
        'beesafe_settings_section_callback',
        'beesafe'
    );

    add_settings_field(
        'beesafe_field_attempts',
        __('Max Login Attempts', 'beesafe'),
        'beesafe_field_attempts_render',
        'beesafe',
        'beesafe_section'
    );

    add_settings_field(
        'beesafe_field_timeout',
        __('Timeout Duration (Minutes)', 'beesafe'),
        'beesafe_field_timeout_render',
        'beesafe',
        'beesafe_section'
    );
}
function beesafe_field_attempts_render() {
    $options = get_option('beesafe_settings');
    ?>
    <input type='number' name='beesafe_settings[beesafe_field_attempts]' value='<?php echo $options['beesafe_field_attempts']; ?>'>
    <?php
}

function beesafe_field_timeout_render() {
    $options = get_option('beesafe_settings');
    ?>
    <input type='number' name='beesafe_settings[beesafe_field_timeout]' value='<?php echo $options['beesafe_field_timeout']; ?>'>
    <?php
}

function beesafe_settings_section_callback() {
    echo __('Set the parameters for login attempts and lockout duration.', 'beesafe');
}
function beesafe_settings_page() {
    ?>
    <form action='options.php' method='post'>
        <h2>BeeSafe Settings</h2>
        <?php
        settings_fields('beesafe');
        do_settings_sections('beesafe');
        submit_button();
        ?>
    </form>
    <?php
}

add_action('init', 'beesafe_disable_login_page_on_lockout');

function beesafe_disable_login_page_on_lockout() {
    // Check if the current request is for the login page
    $is_login_page = isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php';

    if ($is_login_page) {
        global $wpdb;

        $ip_address = $_SERVER['REMOTE_ADDR'];
        $table_name = $wpdb->prefix . 'login_attempts';
        $lockout_duration = get_option('beesafe_settings')['beesafe_field_timeout'] . ' MINUTE'; // Assuming timeout is stored in minutes

        // Retrieve the most recent attempt for this IP address
        $recent_attempt = $wpdb->get_row($wpdb->prepare(
            "SELECT attempt_time FROM $table_name WHERE ip_address = %s ORDER BY attempt_time DESC LIMIT 1",
            $ip_address
        ));

        if ($recent_attempt) {
            $current_time = current_time('timestamp', 1);
            $last_attempt_time = strtotime($recent_attempt->attempt_time);
            $time_diff = $current_time - $last_attempt_time;

            // Check if the last attempt is within the lockout duration
            if ($time_diff < strtotime($lockout_duration, 0)) {
                // Disable the login page by redirecting or displaying a message
                wp_die('The login page is temporarily disabled due to too many failed login attempts. Please try again later.');
            }
        }
    }
}
