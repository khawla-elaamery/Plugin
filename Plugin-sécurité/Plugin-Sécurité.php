
<?php
/*
Plugin Name: Plugin Sécurité
Description: Plugin complet pour renforcer la sécurité de votre site WordPress.
Author: Khawla & Nassima
Fonctionnalités :
- Masque la version WordPress
- Désactive XML-RPC
- Désactive l'éditeur de fichiers
- Bloque les requêtes et URLs malveillantes
- Désactive l'API REST pour les utilisateurs non connectés
- Restreint l'accès à /wp-admin aux non connectés
- Limite les tentatives de connexion (configurable)
- Active un reCAPTCHA Google sur la page de connexion (activable via admin)
- Affiche un mur reCAPTCHA avant tout accès au site
- Ajoute des en-têtes HTTP de sécurité
- Scan des vulnérabilités et ses résultats
- Interface d’administration : nombre de tentatives + activation reCAPTCHA Version: 2.0
*/

// --- MASQUER VERSION WORDPRESS ---
remove_action('wp_head', 'wp_generator');

// --- DÉSACTIVER XML-RPC ---
add_filter('xmlrpc_enabled', '__return_false');

// --- DÉSACTIVER ÉDITEUR FICHIERS ---
define('DISALLOW_FILE_EDIT', true);

// --- BLOQUER REQUÊTES MALICIEUSES ---
function bloquer_requetes_malveillantes() {
    $requetes = ["' OR 1=1", "union select", "base64_", "etc/passwd", "wp-config.php"];
    foreach ($requetes as $mot) {
        if (stripos($_SERVER['REQUEST_URI'], $mot) !== false) {
            wp_die('Requête bloquée pour raison de sécurité.');
        }
    }
}
add_action('init', 'bloquer_requetes_malveillantes');

// --- BLOQUER URL TROP LONGUE ---
function limite_url_longueur() {
    if (strlen($_SERVER['REQUEST_URI']) > 255) {
        wp_die('URL trop longue - Bloquée.');
    }
}
add_action('init', 'limite_url_longueur');

// --- REST API : BLOQUER AUX NON CONNECTÉS ---
add_filter('rest_authentication_errors', function ($result) {
    if (!is_user_logged_in()) {
        return new WP_Error('rest_cannot_access', __('Accès non autorisé à l’API REST.', 'text-domain'), ['status' => 403]);
    }
    return $result;
});

// --- BLOQUER ACCÈS À /wp-admin AUX NON CONNECTÉS ---
function bloquer_wp_admin_non_connectes() {
    if (is_admin() && !defined('DOING_AJAX') && !wp_doing_ajax()) {
        if (!is_user_logged_in()) {
            // Force WordPress à afficher la page 404
            global $wp_query;
            $wp_query->set_404();
            status_header(404);
            nocache_headers();
            include(get_404_template());
            exit;
        }
    }
}
add_action('init', 'bloquer_wp_admin_non_connectes');

// --- LIMITER TENTATIVES DE CONNEXION ---
function custom_login_failed_limit($username) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $options = get_option('plugin_securite_options');
    $max_attempts = $options['max_attempts'] ?? 3;
    $lockout_duration = 15 * MINUTE_IN_SECONDS;

    $attempts = get_transient('login_attempts_' . $ip) ?: 0;
    $attempts++;
    set_transient('login_attempts_' . $ip, $attempts, $lockout_duration);

    if ($attempts >= $max_attempts) {
        set_transient('login_lockout_' . $ip, time(), $lockout_duration);

    $options = get_option('plugin_securite_options');
    $email = !empty($options['alert_email']) ? $options['alert_email'] : get_option('admin_email');
    wp_mail($email, 'Tentatives de connexion bloquées', "IP : $ip\nUtilisateur : $username\nHeure : " . date('Y-m-d H:i:s'));
    }
}
add_action('wp_login_failed', 'custom_login_failed_limit');

function custom_authenticate_user($user, $username, $password) {
    if (get_transient('login_lockout_' . $_SERVER['REMOTE_ADDR'])) {
        return new WP_Error('too_many_attempts', __('Trop de tentatives de connexion. Réessayez plus tard.'));
    }
    return $user;
}
add_filter('authenticate', 'custom_authenticate_user', 30, 3);

function block_login_page_for_locked_ips() {
    if (strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false && get_transient('login_lockout_' . $_SERVER['REMOTE_ADDR'])) {
        wp_die('Accès temporairement bloqué. Trop de tentatives.');
    }
}
add_action('init', 'block_login_page_for_locked_ips');




// --- EN-TÊTES HTTP DE SÉCURITÉ ---
function monplugin_entetes_securite() {
    if (headers_sent()) return;
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: SAMEORIGIN");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Permissions-Policy: geolocation=(), camera=()");
}
add_action('send_headers', 'monplugin_entetes_securite');


// --- INTERFACE D’ADMINISTRATION ---
function plugin_securite_menu() {
add_menu_page('SecurePress','SecurePress','manage_options','plugin_securite','plugin_securite_page','dashicons-shield', 30);
add_submenu_page('plugin_securite','Pare-feu','Pare-feu','manage_options','plugin_securite_firewall','plugin_securite_firewall_page');
add_submenu_page('plugin_securite','Paramètres personnalisés','Paramètres personnalisés','manage_options','plugin_securite_parametres','plugin_paramétre_page');
add_submenu_page('plugin_securite','Scan sécurité','Scan sécurité','manage_options','plugin_securite_scan','plugin_securite_scan_page');
    
   
}
add_action('admin_menu', 'plugin_securite_menu');

// Page principale : Paramètres
function plugin_securite_page() {
    ?>
    <div class="wrap">
        <h1><b>SecurePress</b></h1>
        <br>

<div style="
    background-color: #B0DDEE;
    text-align:left;
    padding: 20px;
    border-radius: 15px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    width: 95%;
    height: 50px;
    margin: 0 auto;
    font-family: sans-serif;
">
        <p>
            <strong>SecurePress</strong> est un plugin de sécurité tout-en-un conçu pour 
            protéger efficacement votre site WordPress contre les attaques courantes, 
            les tentatives de connexion abusives et les comportements suspects.
        </p>
</div>
<br>
<br>
   
        <div style="
    background-color: #B0DDEE;
    text-align:left;
    float:center;
    padding: 20px;
    border-radius: 15px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    width: 95%;
    height: 350px;
    margin: 0 auto;
    font-family: sans-serif;
">

<img src="https://stagiaire.coherencedemos7.fr/wp-content/uploads/2025/05/cropped-cropped-شعار-ذهبي-واسود-حرف-أ-و-س-عن-شركات-التصميم-الجرافيكي-1.png" alt="Image descriptive" style="
        width: 350px;
        height: 300px;
        border-radius: 10px;
        margin-right: 20px;
        float:left;
    ">
    <h2 style="color: #000000;"><b>Fonctionnalités intégrées :</b></h2>
    <ul style="list-style-type: disc; padding-left: 20px; color: #333;">
        <li>Masquage de la version WordPress</li>
        <li>Désactivation de XML-RPC</li>
        <li>Désactivation de l’éditeur de fichiers WordPress</li>
        <li>Blocage des requêtes malveillantes connues (injection SQL, accès non autorisé, etc.)</li>
        <li>Blocage des URLs anormalement longues</li>
        <li>Désactivation de l’API REST pour les utilisateurs non connectés</li>
        <li>Restriction d’accès à l’interface d’administration (/wp-admin) aux utilisateurs connectés uniquement</li>
        <li>Limitation des tentatives de connexion avec verrouillage temporaire</li>
        <li>Ajout de reCAPTCHA Google sur la page de connexion (option activable)</li>
        <li>Mur reCAPTCHA obligatoire avant d'accéder au site (anti-bot)</li>
        <li>Ajout automatique d’en-têtes de sécurité HTTP (HSTS, X-Frame-Options, etc.)</li>
    </ul>
    </div>
<br>
<br>


    <?php
}

function plugin_paramétre_page(){
    ?>
    <div class="wrap">
        <h1><b>Paramétres Personnalisés</b></h1>
        <br>
    <div style="
    background-color: #B0DDEE;
    text-align:left;
    float:center;
    padding: 20px;
    border-radius: 15px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    width: 95%;
    height: 400px;
    margin: 0 auto;
    font-family: sans-serif;
    ">
        <h2 style="color: #000000;"><b>Paramètres personnalisables :</b></h2>
        <form method="post" action="options.php">
            <?php
            settings_fields('plugin_securite_options');
            do_settings_sections('plugin_securite');
            submit_button('Enregistrer les paramètres');
            ?>
        </form>
     </div>
    </div>
    <?php
}

// Sous-menu : reCAPTCHA
function plugin_securite_recaptcha_page() {
    $options = get_option('plugin_securite_options');
    ?>
    <div class="wrap">
        <h1>Paramètres reCAPTCHA</h1>
        <form method="post" action="options.php">
            <?php
            settings_fields('plugin_securite_options');
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Activer reCAPTCHA</th>
                    <td>
                        <input type="checkbox" name="plugin_securite_options[recaptcha_active]" value="1" 
                        <?php checked($options['recaptcha_active'] ?? '', 1); ?> />
                    </td>
                </tr>
            </table>
            <?php submit_button('Enregistrer les paramètres'); ?>
        </form>
    </div>
    <?php
}

// Enregistrement des paramètres
function plugin_securite_settings() {
    register_setting('plugin_securite_options', 'plugin_securite_options');

    add_settings_section('plugin_securite_section', 'Options de sécurité', null, 'plugin_securite');

    add_settings_field('plugin_securite_max_attempts', 'Nombre maximal de tentatives', function () {
        $value = get_option('plugin_securite_options')['max_attempts'] ?? 3;
        echo "<input type='number' name='plugin_securite_options[max_attempts]' value='" . esc_attr($value) . "' />";
    }, 'plugin_securite', 'plugin_securite_section');

    add_settings_field('plugin_securite_recaptcha_active', 'Activer reCAPTCHA', function () {
        $checked = !empty(get_option('plugin_securite_options')['recaptcha_active']) ? 'checked' : '';
        echo "<input type='checkbox' name='plugin_securite_options[recaptcha_active]' value='1' $checked />";
    }, 'plugin_securite', 'plugin_securite_section');

    add_settings_field('plugin_securite_alert_email', 'Adresse e-mail pour les alertes', function () {
        $value = get_option('plugin_securite_options')['alert_email'] ?? '';
        echo "<input type='email' name='plugin_securite_options[alert_email]' value='" . esc_attr($value) . "' />";
    }, 'plugin_securite', 'plugin_securite_section');
}
add_action('admin_init', 'plugin_securite_settings');

add_action('admin_menu', 'securepress_register_menu');

function securepress_register_menu() {
    add_menu_page(
    'Scan de sécurité',                // Titre de la page    
        'SecurePress',             
    'manage_options',                  // Capacité requise
    'plugin-securite-scan',           // Slug
    'plugin_securite_scan_page',      // Fonction callback
    'dashicons-shield-alt',           // Icône
    56                                 // Position
);

}

// Fonction pour scanner les fichiers du dossier wp-content
function securepress_scan_fichiers() {
    global $wpdb;
    $table = $wpdb->prefix . 'plugin_securite_scan';

    // Vider ancienne table scan avant nouveau scan (optionnel)
    $wpdb->query("TRUNCATE TABLE $table");

    $wp_content = WP_CONTENT_DIR;
    $fichiers = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($wp_content));
    
    foreach ($fichiers as $fichier) {
        if ($fichier->isFile()) {
            $chemin = $fichier->getRealPath();
            $taille = filesize($chemin);
            $hash = md5_file($chemin);

            // Insertion dans la base
            $wpdb->insert($table, [
                'filepath' => $chemin,
                'filesize' => $taille,
                'filehash' => $hash,
                'scan_date' => current_time('mysql'),
            ]);
        }
    }
}


// Ajout style CSS pour le graphique
add_action('admin_head', function() {
    echo '<style>
        #chart-container {
            max-width: 600px;
            height: 300px;
            margin-bottom: 20px;
        }
        #chartScan {
            width: 100% !important;
            height: 100% !important;
        }
    </style>';
});

// Page admin plugin

function plugin_securite_scan_page() {
    global $wpdb;
    $table = $wpdb->prefix . 'plugin_securite_scan';

    $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'scan';
    ?>
    <div class="wrap">
        <h1>SecurePress</h1>

        <h2 class="nav-tab-wrapper">
            <a href="?page=plugin-securite-scan&tab=scan" class="nav-tab <?php echo $active_tab == 'scan' ? 'nav-tab-active' : ''; ?>">Scan</a>
            <a href="?page=plugin-securite-scan&tab=resultats" class="nav-tab <?php echo $active_tab == 'resultats' ? 'nav-tab-active' : ''; ?>">Résultats</a>
        </h2>

        <?php
        if ($active_tab == 'scan') {
            ?>
            <form method="post" action="">
                <?php wp_nonce_field('plugin_securite_scan_action', 'plugin_securite_scan_nonce'); ?>
                <input type="submit" name="plugin_securite_scan_submit" class="button button-primary" value="Lancer un scan maintenant" />
            </form>

            <?php
            if (!empty($_POST['plugin_securite_scan_submit']) && check_admin_referer('plugin_securite_scan_action', 'plugin_securite_scan_nonce')) {
                echo '<p>Scan en cours... Merci de patienter.</p>';
                securepress_scan_fichiers();
                echo '<p><strong>Scan terminé.</strong></p>';
            }
        }

        elseif ($active_tab == 'resultats') {
            // Statistiques et graphique
            $total_files = $wpdb->get_var("SELECT COUNT(*) FROM $table");
            $files_modified = $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE filehash != old_filehash");
            if ($total_files == 0) $total_files = 1;

            $data_chart = [
                'labels' => ['Fichiers intacts', 'Fichiers modifiés'],
                'datasets' => [[
                    'data' => [$total_files - $files_modified, $files_modified],
                    'backgroundColor' => ['#4caf50', '#f44336']
                ]]
            ];

            echo '<h2>Statistiques du scan</h2>';
            echo '<div id="chart-container" style="max-width: 500px; height: 300px;"><canvas id="chartScan"></canvas></div>';
            ?>

            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                const ctx = document.getElementById('chartScan').getContext('2d');
                const data = <?php echo json_encode($data_chart); ?>;

                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            data: data.datasets[0].data,
                            backgroundColor: data.datasets[0].backgroundColor
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
            </script>

            <?php
            // Tableau des 10 derniers fichiers modifiés
            $files_modifies = $wpdb->get_results(
                "SELECT filepath, filesize, filehash, old_filehash, scan_date 
                FROM $table 
                WHERE filehash != old_filehash 
                ORDER BY scan_date DESC 
                LIMIT 10",
                ARRAY_A
            );

            echo '<h2>Fichiers modifiés (10 derniers)</h2>';

            if ($files_modifies) {
                echo '<table class="widefat fixed">';
                echo '<thead><tr><th>Fichier</th><th>Taille</th><th>Hash MD5</th><th>Référence</th><th>Date</th></tr></thead><tbody>';
                foreach ($files_modifies as $file) {
                    echo '<tr>';
                    echo '<td>' . esc_html(str_replace(ABSPATH, '', $file['filepath'])) . '</td>';
                    echo '<td>' . number_format_i18n($file['filesize']) . ' octets</td>';
                    echo '<td>' . esc_html($file['filehash']) . '</td>';
                    echo '<td>' . esc_html($file['old_filehash']) . '</td>';
                    echo '<td>' . esc_html($file['scan_date']) . '</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            } else {
                echo '<p>Aucun fichier modifié détecté.</p>';
            }
        }

        
        ?>

    </div>
    <?php
}


// ==========================
// Pare-feu 
// ==========================
add_action('init', 'plugin_securite_firewall');

function plugin_securite_firewall() {
    if (is_admin()) return;

    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $ips_bloquees = get_option('securepress_ips_bloquees', []);
       $patterns_dangereux = [
        '/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',               // Injection SQL simple
        '/(eval\()|(base64_decode\()|(exec\()/i',         // Code PHP
        '/wp-config\.php/i',                                // Accès à fichier
        '/etc\/passwd/i',                                   // Fuite Linux
        '/select.+from/i',                                   // SQL
        '/<script\b[^>]*>/i',                               // XSS
    ];

    // Blocage IP déjà enregistrée
    if (in_array($ip, $ips_bloquees)) {
        status_header(403);
        exit(' Accès bloqué par SecurePress.');
    }
    foreach ($patterns_dangereux as $index => $pattern) {
        if (preg_match($pattern, $uri) || preg_match($pattern, $user_agent)) {
            // Statistiques
            $stats = get_option('securepress_stats', ['total_blocages' => 0, 'regles' => []]);
            $stats['total_blocages']++;
            $stats['regles'][$index] = ($stats['regles'][$index] ?? 0) + 1;
            update_option('securepress_stats', $stats);

            // Ajout IP
            if (!in_array($ip, $ips_bloquees)) {
                $ips_bloquees[] = $ip;
                update_option('securepress_ips_bloquees', $ips_bloquees);
            }

            status_header(403);
            exit(' Requête bloquée par le pare-feu SecurePress.');
        }
    }
}

/* ==========================
    Menu admin
 ========================== */
add_action('admin_menu', 'plugin_securite_admin_menu');

function plugin_securite_admin_menu() {
    add_menu_page(
        'Pare-feu SecurePress',
        'manage_options',
        'securepress-firewall',
        'plugin_securite_firewall_page',
        'dashicons-shield-alt',
        56
    );
}

/* ==========================
    Page admin avec stats + graphique
 ========================== */
function plugin_securite_firewall_page() {
    if (!current_user_can('manage_options')) return;

    $ips_bloquees = get_option('securepress_ips_bloquees', []);
    $stats = get_option('securepress_stats', ['total_blocages' => 0, 'regles' => []]);

    $regles_libelles = [
        0 => 'Injection SQL (%27, --, #)',
        1 => 'Code malveillant (eval, base64_decode)',
        2 => 'Accès wp-config.php',
        3 => 'Fuite /etc/passwd',
        4 => 'Requête SQL (SELECT FROM)',
        5 => 'XSS (<script>)'
    ];

    if (isset($_POST['ip_to_unblock']) && check_admin_referer('unblock_ip_action')) {
        $ip_to_remove = sanitize_text_field($_POST['ip_to_unblock']);
        $ips_bloquees = array_filter($ips_bloquees, fn($ip) => $ip !== $ip_to_remove);
        update_option('securepress_ips_bloquees', $ips_bloquees);
        echo '<div class="notice notice-success"><p>IP débloquée : ' . esc_html($ip_to_remove) . '</p></div>';
    }

    if (isset($_POST['reset_firewall']) && check_admin_referer('reset_firewall_action')) {
        update_option('securepress_ips_bloquees', []);
        $ips_bloquees = [];
        echo '<div class="notice notice-success"><p>Toutes les IP ont été débloquées.</p></div>';
    }

    ?>
     <div class="wrap">
        <h1>Pare-feu SecurePress</h1>

        <h2>Statistiques</h2>
        <ul>
            <li><strong>Total de requêtes bloquées :</strong> <?php echo esc_html($stats['total_blocages']); ?></li>
        </ul>

        <?php if (!empty($stats['regles'])): ?>
            <table class="widefat striped" style="max-width:500px;">
                <thead><tr><th>Test appliqué</th><th>Déclenchements</th></tr></thead>
                <tbody>
                <?php foreach ($stats['regles'] as $index => $count): ?>
                    <tr>
                        <td><?php echo esc_html($regles_libelles[$index] ?? 'Règle inconnue'); ?></td>
                        <td><?php echo esc_html($count); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?> 

        <canvas id="securepressStatsChart" width="600" height="300"></canvas>

        <h2 style="margin-top:40px;">IP bloquées</h2>
        <?php if (empty($ips_bloquees)): ?>
            <p><strong>Aucune IP actuellement bloquée.</strong></p>
        <?php else: ?>
            <table class="widefat striped">
                <thead><tr><th>Adresse IP</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($ips_bloquees as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td>
                            <form method="post">
                                <?php wp_nonce_field('unblock_ip_action'); ?>
                                <input type="hidden" name="ip_to_unblock" value="<?php echo esc_attr($ip); ?>">
                                <input type="submit" class="button button-secondary" value="Débloquer">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" style="margin-top:20px;">
                <?php wp_nonce_field('reset_firewall_action'); ?>
                <input type="submit" name="reset_firewall" class="button button-danger" value="Débloquer toutes les IP">
            </form>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    document.addEventListener("DOMContentLoaded", function () {
        const ctx = document.getElementById('securepressStatsChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: <?php echo json_encode(array_values($regles_libelles)); ?>,
                datasets: [{
                    label: 'Déclenchements',
                    data: <?php
                        $data = [];
                        foreach (array_keys($regles_libelles) as $i) {
                            $data[] = $stats['regles'][$i] ?? 0;
                        }
                        echo json_encode($data);
                    ?>,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Blocages'
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    title: {
                        display: true,
                        text: 'Attaques détectées par type'
                    }
                }
            }
        });
    });
    </script>
    <?php
}
