<?php
/*
Plugin Name: Dolutech Blacklist Security
Description: Protege o site contra IPs maliciosos usando a blacklist da Dolutech e implementa proteção contra ataques de força bruta.
Version: 0.1.0
Author: Lucas Catão de Moraes
Author URI: https://dolutech.com
License: GPL2
Requires at least: 6.6.0
Requires PHP: 8.3
*/

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class Dolutech_Blacklist_Security {

    private $blacklist_option = 'dolutech_blacklist_ips';
    private $blacklist_url = 'https://raw.githubusercontent.com/dolutech/blacklist-dolutech/main/Black-list-semanal-dolutech.txt';
    private $log_option = 'dolutech_security_logs';
    private $brute_force_option = 'dolutech_brute_force_settings';
    private $blocked_ips_option = 'dolutech_brute_force_blocked_ips';
    private $whitelist_option = 'dolutech_whitelisted_ips';
    private $ddns_option = 'dolutech_ddns_settings';

    public function __construct() {
        // Adiciona o menu do plugin
        add_action('admin_menu', [$this, 'create_plugin_menu']);
        // Inicializa o plugin
        add_action('init', [$this, 'initialize_plugin'], 1);
        register_activation_hook(__FILE__, [$this, 'activate_plugin']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate_plugin']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
    }

    public function initialize_plugin() {
        // Bloqueia IPs após o WordPress estar totalmente carregado
        add_action('wp', [$this, 'block_blacklisted_ips'], 1);
        // Bloqueia IPs na página de login
        add_action('login_init', [$this, 'block_blacklisted_ips_login'], 1);

        // Hooks de proteção contra força bruta
        add_action('wp_login_failed', [$this, 'handle_failed_login']);
        add_filter('authenticate', [$this, 'check_brute_force_protection'], 30, 3);

        // Tarefas agendadas
        add_action('dolutech_daily_update', [$this, 'update_blacklist']);
        add_action('dolutech_daily_ddns_update', [$this, 'update_ddns_ip']);
        add_action('dolutech_daily_log_email', [$this, 'send_daily_log_email']);

        if (!wp_next_scheduled('dolutech_daily_update')) {
            wp_schedule_event(time(), 'daily', 'dolutech_daily_update');
        }

        if (!wp_next_scheduled('dolutech_daily_ddns_update')) {
            wp_schedule_event(time(), 'daily', 'dolutech_daily_ddns_update');
        }

        // Ações para logs
        add_action('admin_post_dolutech_download_logs', [$this, 'download_logs']);
        add_action('admin_post_dolutech_send_logs_email', [$this, 'send_logs_email_now']);
        add_action('admin_post_dolutech_clear_logs', [$this, 'clear_logs']);
    }

    public function create_plugin_menu() {
        add_menu_page(
            'Dolutech Blacklist Security',
            'Dolutech Security',
            'manage_options',
            'dolutech-security',
            [$this, 'plugin_settings_page'],
            'dashicons-lock',
            81
        );

        add_submenu_page(
            'dolutech-security',
            'Brute-force',
            'Brute-force',
            'manage_options',
            'dolutech-brute-force',
            [$this, 'plugin_brute_force_page']
        );

        add_submenu_page(
            'dolutech-security',
            'Logs',
            'Logs',
            'manage_options',
            'dolutech-logs',
            [$this, 'plugin_logs_page']
        );
    }

    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'dolutech-security') === false) {
            return;
        }
        wp_enqueue_style('bootstrap-css', 'https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css');
        wp_enqueue_script('bootstrap-js', 'https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js', ['jquery'], null, true);
    }

    /*** Adiciona o IP do Admin à Whitelist durante a ativação ***/
    public function activate_plugin() {
        update_option('dolutech_blacklist_active', '1');
        $this->update_blacklist();

        // Adiciona o IP do administrador à whitelist na ativação
        $admin_ip = $this->get_user_ip();
        $this->add_to_whitelist($admin_ip);
    }

    public function deactivate_plugin() {
        delete_option('dolutech_blacklist_active');
        delete_option($this->blacklist_option);
        delete_option($this->log_option);
        delete_option($this->brute_force_option);
        delete_option($this->blocked_ips_option);
        delete_option($this->whitelist_option);
        delete_option($this->ddns_option);
        wp_clear_scheduled_hook('dolutech_daily_update');
        wp_clear_scheduled_hook('dolutech_daily_log_email');
        wp_clear_scheduled_hook('dolutech_daily_ddns_update');
    }

    /*** Página de Configurações do Plugin ***/
    public function plugin_settings_page() {
        // Verifica se o usuário tem permissão
        if (!current_user_can('manage_options')) {
            return;
        }

        $messages = [];

        // Processa a ativação/desativação da blacklist
        if (isset($_POST['dolutech_activate_blacklist']) && check_admin_referer('dolutech_activate_action', 'dolutech_activate_nonce')) {
            update_option('dolutech_blacklist_active', '1');
            $messages[] = '<div class="alert alert-success">Blacklist ativada com sucesso.</div>';
        }

        if (isset($_POST['dolutech_deactivate_blacklist']) && check_admin_referer('dolutech_deactivate_action', 'dolutech_deactivate_nonce')) {
            update_option('dolutech_blacklist_active', '0');
            $messages[] = '<div class="alert alert-warning">Blacklist desativada.</div>';
        }

        // Processa a atualização manual da blacklist
        if (isset($_POST['dolutech_force_update']) && check_admin_referer('dolutech_force_update_action', 'dolutech_force_update_nonce')) {
            $this->update_blacklist(true);
            $messages[] = '<div class="alert alert-info">Blacklist atualizada manualmente com sucesso.</div>';
        }

        // Processa a remoção de IP
        if (isset($_POST['dolutech_remove_ip']) && check_admin_referer('dolutech_remove_ip_action', 'dolutech_remove_ip_nonce')) {
            $ip_to_remove = sanitize_text_field($_POST['dolutech_ip_remove']);
            if ($this->remove_ip($ip_to_remove)) {
                $messages[] = '<div class="alert alert-success">IP removido da blacklist com sucesso.</div>';
            } else {
                $messages[] = '<div class="alert alert-danger">IP não encontrado na blacklist.</div>';
            }
        }

        // Processa a adição de IP
        if (isset($_POST['dolutech_add_ip']) && check_admin_referer('dolutech_add_ip_action', 'dolutech_add_ip_nonce')) {
            $ip_to_add = sanitize_text_field($_POST['dolutech_ip_add']);
            $reason = sanitize_textarea_field($_POST['dolutech_reason']);
            $report = isset($_POST['dolutech_report']) ? true : false;

            if ($this->add_ip($ip_to_add)) {
                $messages[] = '<div class="alert alert-success">IP adicionado à blacklist com sucesso.</div>';

                if ($report) {
                    $email_sent = $this->send_report_email($ip_to_add, $reason);
                    if ($email_sent) {
                        $messages[] = '<div class="alert alert-info">IP reportado à Dolutech com sucesso.</div>';
                    } else {
                        $messages[] = '<div class="alert alert-warning">Falha ao enviar o email de reporte.</div>';
                    }
                }
            } else {
                $messages[] = '<div class="alert alert-danger">O IP fornecido é inválido ou já está na blacklist.</div>';
            }
        }

        // Processa whitelist addition
        if (isset($_POST['dolutech_add_whitelist']) && check_admin_referer('dolutech_add_whitelist_action', 'dolutech_add_whitelist_nonce')) {
            $ip = sanitize_text_field($_POST['dolutech_whitelist_ip']);
            if ($this->add_to_whitelist($ip)) {
                $messages[] = '<div class="alert alert-success">Seu IP foi adicionado à whitelist com sucesso.</div>';
            } else {
                $messages[] = '<div class="alert alert-danger">O IP fornecido é inválido ou já está na whitelist.</div>';
            }
        }

        // Processa DDNS addition
        if (isset($_POST['dolutech_add_ddns']) && check_admin_referer('dolutech_add_ddns_action', 'dolutech_add_ddns_nonce')) {
            $ddns = sanitize_text_field($_POST['dolutech_ddns']);
            if ($this->add_ddns($ddns)) {
                $messages[] = '<div class="alert alert-success">DDNS adicionado com sucesso. O plugin irá atualizar o IP diariamente.</div>';
            } else {
                $messages[] = '<div class="alert alert-danger">O DDNS fornecido é inválido.</div>';
            }
        }

        // Processa DDNS removal
        if (isset($_POST['dolutech_remove_ddns']) && check_admin_referer('dolutech_remove_ddns_action', 'dolutech_remove_ddns_nonce')) {
            $this->remove_ddns();
            $messages[] = '<div class="alert alert-success">DDNS removido com sucesso.</div>';
        }

        $blacklist_active = get_option('dolutech_blacklist_active', '1');
        $blacklisted_ips = get_option($this->blacklist_option, []);
        $total_ips = is_array($blacklisted_ips) ? count($blacklisted_ips) : 0;
        $whitelisted_ips = get_option($this->whitelist_option, []);
        $ddns_settings = get_option($this->ddns_option, []);

        ?>
        <!-- HTML da página de configurações -->
        <div class="wrap">
            <div class="container mt-4">
                <h1 class="mb-4">Dolutech Blacklist Security</h1>

                <?php foreach ($messages as $message) {
                    echo $message;
                } ?>

                <!-- Seção de Ativação/Desativação -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Status da Blacklist</h4>
                        <p class="card-text">
                            <?php
                            if ($blacklist_active === '1') {
                                echo '<span class="badge badge-success">Ativa</span>';
                            } else {
                                echo '<span class="badge badge-secondary">Desativada</span>';
                            }
                            ?>
                        </p>
                        <form method="post" class="d-inline">
                            <?php
                            if ($blacklist_active === '1') {
                                wp_nonce_field('dolutech_deactivate_action', 'dolutech_deactivate_nonce');
                                echo '<input type="submit" name="dolutech_deactivate_blacklist" value="Desativar" class="btn btn-warning">';
                            } else {
                                wp_nonce_field('dolutech_activate_action', 'dolutech_activate_nonce');
                                echo '<input type="submit" name="dolutech_activate_blacklist" value="Ativar" class="btn btn-success">';
                            }
                            ?>
                        </form>
                        <!-- Botão para atualizar a blacklist -->
                        <form method="post" class="d-inline ml-2">
                            <?php wp_nonce_field('dolutech_force_update_action', 'dolutech_force_update_nonce'); ?>
                            <input type="submit" name="dolutech_force_update" value="Forçar Atualização da Blacklist" class="btn btn-info">
                        </form>
                        <p class="mt-2 text-muted">A blacklist é atualizada automaticamente diariamente, mas você pode forçar uma atualização manualmente.</p>
                        <p>Total de IPs bloqueados: <strong><?php echo $total_ips; ?></strong></p>
                    </div>
                </div>

                <!-- Whitelist Section -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">IP Sempre Permitido (Whitelist)</h4>
                        <?php if (!empty($whitelisted_ips)) : ?>
                            <p>Seu IP está na whitelist e nunca será bloqueado.</p>
                            <p><strong>IP:</strong> <?php echo esc_html($whitelisted_ips[0]); ?></p>
                        <?php else : ?>
                            <p>Você pode adicionar seu IP para nunca ser bloqueado. Isso é recomendado apenas se você tiver IP fixo.</p>
                            <form method="post">
                                <?php wp_nonce_field('dolutech_add_whitelist_action', 'dolutech_add_whitelist_nonce'); ?>
                                <input type="hidden" name="dolutech_whitelist_ip" value="<?php echo esc_attr($this->get_user_ip()); ?>">
                                <input type="submit" name="dolutech_add_whitelist" value="Adicionar meu IP à Whitelist" class="btn btn-primary">
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- DDNS Section -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Adicionar DDNS à Whitelist</h4>
                        <?php if (!empty($ddns_settings)) : ?>
                            <p>Seu DDNS está configurado e será atualizado diariamente.</p>
                            <p><strong>DDNS:</strong> <?php echo esc_html($ddns_settings['ddns']); ?></p>
                            <p><strong>IP Atual:</strong> <?php echo esc_html($ddns_settings['ip']); ?></p>
                            <form method="post">
                                <?php wp_nonce_field('dolutech_remove_ddns_action', 'dolutech_remove_ddns_nonce'); ?>
                                <input type="submit" name="dolutech_remove_ddns" value="Remover DDNS" class="btn btn-danger">
                            </form>
                        <?php else : ?>
                            <p>Se você possui um DDNS, pode adicioná-lo aqui para que seu IP seja atualizado diariamente e nunca seja bloqueado.</p>
                            <form method="post">
                                <?php wp_nonce_field('dolutech_add_ddns_action', 'dolutech_add_ddns_nonce'); ?>
                                <div class="form-group">
                                    <label for="dolutech_ddns">Endereço DDNS:</label>
                                    <input type="text" name="dolutech_ddns" id="dolutech_ddns" class="form-control" required>
                                </div>
                                <input type="submit" name="dolutech_add_ddns" value="Adicionar DDNS" class="btn btn-primary">
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Formulário para adicionar IP -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Adicionar IP à Blacklist</h4>
                        <form method="post">
                            <?php wp_nonce_field('dolutech_add_ip_action', 'dolutech_add_ip_nonce'); ?>
                            <div class="form-group">
                                <label for="dolutech_ip_add">Endereço IP:</label>
                                <input type="text" name="dolutech_ip_add" id="dolutech_ip_add" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="dolutech_reason">Motivo:</label>
                                <textarea name="dolutech_reason" id="dolutech_reason" class="form-control" rows="3" required></textarea>
                            </div>
                            <div class="custom-control custom-switch mb-3">
                                <input type="checkbox" class="custom-control-input" id="dolutech_report" name="dolutech_report">
                                <label class="custom-control-label" for="dolutech_report">Reportar este IP para a equipe Dolutech</label>
                            </div>
                            <input type="submit" name="dolutech_add_ip" value="Adicionar IP" class="btn btn-danger">
                        </form>
                    </div>
                </div>

                <!-- Formulário para remover IP -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Remover IP da Blacklist</h4>
                        <form method="post">
                            <?php wp_nonce_field('dolutech_remove_ip_action', 'dolutech_remove_ip_nonce'); ?>
                            <div class="form-group">
                                <label for="dolutech_ip_remove">Endereço IP:</label>
                                <input type="text" name="dolutech_ip_remove" id="dolutech_ip_remove" class="form-control" required>
                            </div>
                            <input type="submit" name="dolutech_remove_ip" value="Remover IP" class="btn btn-success">
                        </form>
                    </div>
                </div>

                <!-- Informações adicionais -->
                <div class="card">
                    <div class="card-body">
                        <p>A Blacklist é mantida e atualizada diariamente por <a href="https://dolutech.com" target="_blank">Dolutech</a>.</p>
                        <p>Para denunciar abuso de um IP, envie um email para: <a href="mailto:abuse@dolutech.com">abuse@dolutech.com</a></p>
                        <p class="mt-4">Desenvolvido por Lucas Catão de Moraes.</p>
                    </div>
                </div>

            </div>
        </div>
        <?php
    }

    /*** Página de Proteção contra Força Bruta ***/
    public function plugin_brute_force_page() {
        // Verifica se o usuário tem permissão
        if (!current_user_can('manage_options')) {
            return;
        }

        $messages = [];

        // Processa o formulário de configurações
        if (isset($_POST['dolutech_save_brute_force']) && check_admin_referer('dolutech_brute_force_action', 'dolutech_brute_force_nonce')) {
            $enabled = isset($_POST['dolutech_brute_force_enabled']) ? '1' : '0';
            $attempts = intval($_POST['dolutech_brute_force_attempts']);
            $lockout_duration = intval($_POST['dolutech_brute_force_duration']);

            $settings = [
                'enabled' => $enabled,
                'attempts' => $attempts,
                'duration' => $lockout_duration,
            ];

            update_option($this->brute_force_option, $settings);

            $messages[] = '<div class="alert alert-success">Configurações de proteção de força bruta atualizadas com sucesso.</div>';
        }

        // Processa ações de IP (remover bloqueio temporário, adicionar à blacklist)
        if (isset($_POST['ip']) && check_admin_referer('dolutech_brute_force_ip_action', 'dolutech_brute_force_ip_nonce')) {
            $ip = sanitize_text_field($_POST['ip']);
            if (isset($_POST['unblock_ip'])) {
                $this->unblock_ip($ip);
                $messages[] = '<div class="alert alert-success">IP desbloqueado com sucesso.</div>';
            } elseif (isset($_POST['blacklist_ip'])) {
                $this->add_ip($ip);
                $this->unblock_ip($ip);
                // Opção para reportar IP
                if (isset($_POST['report_ip'])) {
                    $reason = 'Bloqueado por tentativas de login de força bruta.';
                    $this->send_report_email($ip, $reason, $this->get_brute_force_log($ip));
                    $messages[] = '<div class="alert alert-info">IP adicionado à blacklist e reportado à Dolutech.</div>';
                } else {
                    $messages[] = '<div class="alert alert-success">IP adicionado à blacklist.</div>';
                }
            }
        }

        // Obtém as configurações atuais
        $brute_force_settings = get_option($this->brute_force_option, [
            'enabled' => '0',
            'attempts' => 5,
            'duration' => 60,
        ]);
        $blocked_ips = get_option($this->blocked_ips_option, []);

        ?>
        <!-- HTML da página de proteção contra força bruta -->
        <div class="wrap">
            <div class="container mt-4">
                <h1 class="mb-4">Proteção contra Força Bruta</h1>

                <?php foreach ($messages as $message) {
                    echo $message;
                } ?>

                <!-- Configurações de Força Bruta -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Configurações</h4>
                        <form method="post">
                            <?php wp_nonce_field('dolutech_brute_force_action', 'dolutech_brute_force_nonce'); ?>
                            <div class="custom-control custom-switch mb-3">
                                <input type="checkbox" class="custom-control-input" id="dolutech_brute_force_enabled" name="dolutech_brute_force_enabled" <?php checked($brute_force_settings['enabled'], '1'); ?>>
                                <label class="custom-control-label" for="dolutech_brute_force_enabled">Ativar proteção contra força bruta</label>
                            </div>
                            <div class="form-group">
                                <label for="dolutech_brute_force_attempts">Número de tentativas antes do bloqueio:</label>
                                <input type="number" name="dolutech_brute_force_attempts" id="dolutech_brute_force_attempts" class="form-control" value="<?php echo esc_attr($brute_force_settings['attempts']); ?>" min="1" required>
                            </div>
                            <div class="form-group">
                                <label for="dolutech_brute_force_duration">Duração do bloqueio (minutos):</label>
                                <input type="number" name="dolutech_brute_force_duration" id="dolutech_brute_force_duration" class="form-control" value="<?php echo esc_attr($brute_force_settings['duration']); ?>" min="1" required>
                            </div>
                            <input type="submit" name="dolutech_save_brute_force" value="Salvar Configurações" class="btn btn-primary">
                        </form>
                    </div>
                </div>

                <!-- IPs Bloqueados -->
                <?php
                // Filtra apenas os IPs que estão bloqueados atualmente
                $currently_blocked_ips = array_filter($blocked_ips, function($data) {
                    return isset($data['blocked_until']) && $data['blocked_until'] > time();
                });
                if (!empty($currently_blocked_ips)) : ?>
                    <div class="card mb-4">
                        <div class="card-body">
                            <h4 class="card-title">IPs Temporariamente Bloqueados</h4>
                            <table class="table table-bordered">
                                <thead>
                                    <tr>
                                        <th>Endereço IP</th>
                                        <th>Tentativas</th>
                                        <th>Tempo Restante de Bloqueio</th>
                                        <th>Ações</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($currently_blocked_ips as $ip => $data) : ?>
                                        <tr>
                                            <td><?php echo esc_html($ip); ?></td>
                                            <td><?php echo esc_html($data['attempts']); ?></td>
                                            <td>
                                                <?php
                                                $remaining = ($data['blocked_until'] - time()) / 60;
                                                echo esc_html(round($remaining)) . ' minutos';
                                                ?>
                                            </td>
                                            <td>
                                                <form method="post" style="display:inline;">
                                                    <?php wp_nonce_field('dolutech_brute_force_ip_action', 'dolutech_brute_force_ip_nonce'); ?>
                                                    <input type="hidden" name="ip" value="<?php echo esc_attr($ip); ?>">
                                                    <input type="submit" name="unblock_ip" value="Desbloquear" class="btn btn-success btn-sm">
                                                </form>
                                                <form method="post" style="display:inline;">
                                                    <?php wp_nonce_field('dolutech_brute_force_ip_action', 'dolutech_brute_force_ip_nonce'); ?>
                                                    <input type="hidden" name="ip" value="<?php echo esc_attr($ip); ?>">
                                                    <input type="checkbox" name="report_ip" id="report_<?php echo esc_attr($ip); ?>">
                                                    <label for="report_<?php echo esc_attr($ip); ?>">Reportar</label>
                                                    <input type="submit" name="blacklist_ip" value="Bloquear Permanentemente" class="btn btn-danger btn-sm">
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php else : ?>
                    <div class="card mb-4">
                        <div class="card-body">
                            <p>Nenhum IP está temporariamente bloqueado no momento.</p>
                        </div>
                    </div>
                <?php endif; ?>

            </div>
        </div>
        <?php
    }

    /*** Página de Logs ***/
    public function plugin_logs_page() {
        // Verifica se o usuário tem permissão
        if (!current_user_can('manage_options')) {
            return;
        }

        $messages = [];

        // Processa configurações de logs
        if (isset($_POST['dolutech_save_logs_settings']) && check_admin_referer('dolutech_logs_settings_action', 'dolutech_logs_settings_nonce')) {
            $log_email_enabled = isset($_POST['dolutech_log_email_enabled']) ? '1' : '0';
            $log_email_address = sanitize_email($_POST['dolutech_log_email_address']);

            update_option('dolutech_log_email_enabled', $log_email_enabled);
            update_option('dolutech_log_email_address', $log_email_address);

            // Agenda ou limpa o agendamento do email diário de logs
            if ($log_email_enabled === '1') {
                if (!wp_next_scheduled('dolutech_daily_log_email')) {
                    wp_schedule_event(time(), 'daily', 'dolutech_daily_log_email');
                }
            } else {
                wp_clear_scheduled_hook('dolutech_daily_log_email');
            }

            $messages[] = '<div class="alert alert-success">Configurações de logs atualizadas com sucesso.</div>';
        }

        $log_email_enabled = get_option('dolutech_log_email_enabled', '0');
        $log_email_address = get_option('dolutech_log_email_address', '');

        $logs = get_option($this->log_option, []);

        ?>
        <!-- HTML da página de logs -->
        <div class="wrap">
            <div class="container mt-4">
                <h1 class="mb-4">Logs do Dolutech Blacklist Security</h1>

                <?php foreach ($messages as $message) {
                    echo $message;
                } ?>

                <!-- Configurações de Logs -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Configurações de Logs</h4>
                        <form method="post">
                            <?php wp_nonce_field('dolutech_logs_settings_action', 'dolutech_logs_settings_nonce'); ?>
                            <div class="form-group">
                                <label for="dolutech_log_email_address">Endereço de Email para Receber os Logs:</label>
                                <input type="email" name="dolutech_log_email_address" id="dolutech_log_email_address" class="form-control" value="<?php echo esc_attr($log_email_address); ?>">
                            </div>
                            <div class="custom-control custom-switch mb-3">
                                <input type="checkbox" class="custom-control-input" id="dolutech_log_email_enabled" name="dolutech_log_email_enabled" <?php checked($log_email_enabled, '1'); ?>>
                                <label class="custom-control-label" for="dolutech_log_email_enabled">Ativar envio diário de logs por email</label>
                            </div>
                            <input type="submit" name="dolutech_save_logs_settings" value="Salvar Configurações" class="btn btn-primary">
                        </form>
                    </div>
                </div>

                <!-- Exibição de Logs -->
                <div class="card mb-4">
                    <div class="card-body">
                        <h4 class="card-title">Logs Recentes</h4>
                        <?php if (!empty($logs)) : ?>
                            <pre style="background-color: #f8f9fa; padding: 15px;"><?php echo esc_html(implode("\n", array_slice($logs, -100))); ?></pre>
                            <form method="get" action="<?php echo admin_url('admin-post.php'); ?>" style="display:inline;">
                                <?php wp_nonce_field('dolutech_download_logs_action', 'dolutech_download_logs_nonce'); ?>
                                <input type="hidden" name="action" value="dolutech_download_logs">
                                <input type="submit" name="dolutech_download_logs" value="Baixar Logs em TXT" class="btn btn-secondary mr-2">
                            </form>
                            <form method="post" action="<?php echo admin_url('admin-post.php'); ?>" style="display:inline;">
                                <?php wp_nonce_field('dolutech_send_logs_email_action', 'dolutech_send_logs_email_nonce'); ?>
                                <input type="hidden" name="action" value="dolutech_send_logs_email">
                                <input type="submit" name="dolutech_send_logs_email" value="Enviar Logs por Email" class="btn btn-secondary mr-2">
                            </form>
                            <form method="post" action="<?php echo admin_url('admin-post.php'); ?>" style="display:inline;">
                                <?php wp_nonce_field('dolutech_clear_logs_action', 'dolutech_clear_logs_nonce'); ?>
                                <input type="hidden" name="action" value="dolutech_clear_logs">
                                <input type="submit" name="dolutech_clear_logs" value="Limpar Logs" class="btn btn-danger">
                            </form>
                        <?php else : ?>
                            <p>Nenhum log disponível.</p>
                        <?php endif; ?>
                    </div>
                </div>

            </div>
        </div>
        <?php
    }

    /*** Função para Download dos Logs ***/
    public function download_logs() {
        // Verifica permissões
        if (!current_user_can('manage_options')) {
            wp_die('Você não tem permissão para acessar esta página.');
        }

        // Verifica o nonce
        if (!isset($_GET['dolutech_download_logs_nonce']) || !wp_verify_nonce($_GET['dolutech_download_logs_nonce'], 'dolutech_download_logs_action')) {
            wp_die('Falha na verificação de segurança.');
        }

        $logs = get_option($this->log_option, []);
        $log_content = implode("\n", $logs);

        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="dolutech_security_logs.txt"');
        echo $log_content;
        exit;
    }

    /*** Função para Enviar Logs por Email Agora ***/
    public function send_logs_email_now() {
        // Verifica permissões
        if (!current_user_can('manage_options')) {
            wp_die('Você não tem permissão para acessar esta página.');
        }

        // Verifica o nonce
        if (!isset($_POST['dolutech_send_logs_email_nonce']) || !wp_verify_nonce($_POST['dolutech_send_logs_email_nonce'], 'dolutech_send_logs_email_action')) {
            wp_die('Falha na verificação de segurança.');
        }

        $log_email_address = get_option('dolutech_log_email_address', '');
        $logs = get_option($this->log_option, []);

        if (!empty($log_email_address) && !empty($logs)) {
            $subject = 'Logs do Dolutech Blacklist Security';
            $message = '
            <html>
            <head>
              <title>Logs do Dolutech Blacklist Security</title>
            </head>
            <body>
              <h2>Logs Recentes</h2>
              <pre style="background-color:#f8f9fa;padding:15px;">' . esc_html(implode("\n", $logs)) . '</pre>
              <br>
              <p>Este email foi enviado pelo Plugin Dolutech Blacklist Security.</p>
            </body>
            </html>
            ';
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $sent = wp_mail($log_email_address, $subject, $message, $headers);
            if ($sent) {
                $this->log_event('Logs enviados manualmente por email para ' . $log_email_address);
                wp_redirect(admin_url('admin.php?page=dolutech-logs&logs_sent=1'));
                exit;
            } else {
                wp_die('Falha ao enviar os logs por email.');
            }
        } else {
            wp_die('Endereço de email não configurado ou logs vazios.');
        }
    }

    /*** Função para Limpar Logs ***/
    public function clear_logs() {
        // Verifica permissões
        if (!current_user_can('manage_options')) {
            wp_die('Você não tem permissão para acessar esta página.');
        }

        // Verifica o nonce
        if (!isset($_POST['dolutech_clear_logs_nonce']) || !wp_verify_nonce($_POST['dolutech_clear_logs_nonce'], 'dolutech_clear_logs_action')) {
            wp_die('Falha na verificação de segurança.');
        }

        // Limpa os logs
        update_option($this->log_option, []);
        $this->log_event('Logs limpos manualmente pelo usuário.');

        wp_redirect(admin_url('admin.php?page=dolutech-logs&logs_cleared=1'));
        exit;
    }

    /*** Atualização da Blacklist ***/
    public function update_blacklist($manual = false) {
        $response = wp_remote_get($this->blacklist_url);

        if (is_wp_error($response)) {
            $this->log_event('Falha ao atualizar a blacklist: ' . $response->get_error_message());
            return;
        }

        $body = wp_remote_retrieve_body($response);

        // Verifica se o corpo da resposta não está vazio
        if (empty($body)) {
            $this->log_event('Falha ao atualizar a blacklist: resposta vazia.');
            return;
        }

        $lines = explode("\n", $body);
        $ips = [];

        foreach ($lines as $line) {
            $line = trim($line);
            // Ignora linhas vazias ou comentários
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }

            // Valida se é um IP válido (IPv4 ou IPv6)
            if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                $ips[] = $line;
            } else {
                $this->log_event('IP inválido ignorado na blacklist: ' . $line);
            }
        }

        // Remove duplicatas e reindexa o array
        $ips = array_values(array_unique($ips));

        if (!empty($ips)) {
            update_option($this->blacklist_option, $ips);
            $this->log_event('Blacklist atualizada' . ($manual ? ' manualmente' : '') . '. Total de IPs: ' . count($ips));
        } else {
            $this->log_event('Falha ao atualizar a blacklist: nenhuma entrada válida encontrada.');
        }
    }

    /*** Bloqueio de IPs ***/
    public function block_blacklisted_ips() {
        // Assegura que as opções estão carregadas
        if (!function_exists('get_option')) {
            require_once(ABSPATH . 'wp-includes/option.php');
        }

        // Verifica se a blacklist está ativa
        if (get_option('dolutech_blacklist_active', '1') !== '1') {
            return;
        }

        $blacklisted_ips = get_option($this->blacklist_option, []);
        $whitelisted_ips = get_option($this->whitelist_option, []);
        $blocked_ips = get_option($this->blocked_ips_option, []);

        $user_ip = $this->get_user_ip();

        // Verifica se o IP está na whitelist
        if (in_array($user_ip, $whitelisted_ips)) {
            return;
        }

        // Verifica se o IP está na blacklist
        if (in_array($user_ip, $blacklisted_ips)) {
            $this->log_event('Acesso bloqueado para IP (Blacklist): ' . $user_ip);
            $this->block_access();
        }

        // Verifica proteção contra força bruta
        if ($this->is_ip_temporarily_blocked($user_ip)) {
            $this->log_event('Acesso bloqueado temporariamente para IP (Brute-force): ' . $user_ip);
            $this->block_access(true);
        }
    }

    /*** Bloqueio de IPs na página de login ***/
    public function block_blacklisted_ips_login() {
        $user_ip = $this->get_user_ip();

        // Verifica se o IP está na whitelist
        $whitelisted_ips = get_option($this->whitelist_option, []);
        if (in_array($user_ip, $whitelisted_ips)) {
            return;
        }

        // Verifica se o IP está na blacklist
        $blacklisted_ips = get_option($this->blacklist_option, []);
        if (in_array($user_ip, $blacklisted_ips)) {
            $this->log_event('Acesso bloqueado para IP (Blacklist) na página de login: ' . $user_ip);
            $this->block_access();
        }

        // Verifica proteção contra força bruta
        if ($this->is_ip_temporarily_blocked($user_ip)) {
            $this->log_event('Acesso bloqueado temporariamente para IP (Brute-force) na página de login: ' . $user_ip);
            $this->block_access(true);
        }
    }

    /*** Função para Bloquear Acesso ***/
    private function block_access($temporary = false) {
        status_header(403);
        if ($temporary) {
            $message = 'Seu IP foi temporariamente bloqueado devido a várias tentativas de login falhadas. Tente novamente mais tarde.';
            wp_die($message, 'Acesso Bloqueado Temporariamente', ['response' => 403]);
        } else {
            $message = 'Seu IP encontra-se na Blacklist da Dolutech. Caso acredite que foi um erro, envie um email para <a href="mailto:abuse@dolutech.com">abuse@dolutech.com</a> e informe o motivo.';
            wp_die($message, 'Acesso Bloqueado', ['response' => 403]);
        }
    }

    /*** Função para Obter o IP Real do Usuário ***/
    public function get_user_ip() {
        $ip = '';

        // Verifica se há um IP válido em HTTP_X_FORWARDED_FOR
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($ip_list as $ip_addr) {
                $ip_addr = trim($ip_addr);
                if (filter_var($ip_addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                    $ip = $ip_addr;
                    break;
                }
            }
        }

        // Se não, usa REMOTE_ADDR
        if (empty($ip) && !empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        // Se ainda não encontrado, define como 0.0.0.0
        if (empty($ip)) {
            $ip = '0.0.0.0';
        }

        return $ip;
    }

    /*** Funções da Whitelist ***/
    public function add_to_whitelist($ip) {
        $whitelisted_ips = get_option($this->whitelist_option, []);
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) && !in_array($ip, $whitelisted_ips)) {
            $whitelisted_ips[] = $ip;
            update_option($this->whitelist_option, $whitelisted_ips);
            $this->log_event('IP adicionado à whitelist: ' . $ip);
            return true;
        }
        return false;
    }

    public function remove_from_whitelist($ip) {
        $whitelisted_ips = get_option($this->whitelist_option, []);
        $key = array_search($ip, $whitelisted_ips);
        if ($key !== false) {
            unset($whitelisted_ips[$key]);
            update_option($this->whitelist_option, array_values($whitelisted_ips));
            $this->log_event('IP removido da whitelist: ' . $ip);
        }
    }

    /*** Funções de DDNS ***/
    public function add_ddns($ddns) {
        $ddns = trim($ddns);
        $resolved_ip = gethostbyname($ddns);
        if ($resolved_ip !== $ddns && filter_var($resolved_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            $ip = $resolved_ip;
            $settings = [
                'ddns' => $ddns,
                'ip' => $ip,
            ];
            update_option($this->ddns_option, $settings);
            $this->add_to_whitelist($ip);
            $this->log_event('DDNS adicionado: ' . $ddns . ' (IP: ' . $ip . ')');
            return true;
        }
        return false;
    }

    public function remove_ddns() {
        $settings = get_option($this->ddns_option, []);
        if (!empty($settings)) {
            $this->remove_from_whitelist($settings['ip']);
            delete_option($this->ddns_option);
            $this->log_event('DDNS removido: ' . $settings['ddns']);
        }
    }

    public function update_ddns_ip() {
        $settings = get_option($this->ddns_option, []);
        if (!empty($settings)) {
            $new_ip = gethostbyname($settings['ddns']);
            if ($new_ip !== $settings['ddns'] && filter_var($new_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                if ($new_ip !== $settings['ip']) {
                    $this->remove_from_whitelist($settings['ip']);
                    $this->add_to_whitelist($new_ip);
                    $settings['ip'] = $new_ip;
                    update_option($this->ddns_option, $settings);
                    $this->log_event('IP do DDNS atualizado: ' . $settings['ddns'] . ' (Novo IP: ' . $new_ip . ')');
                }
            }
        }
    }

    /*** Proteção contra Força Bruta ***/
    public function handle_failed_login($username) {
        $settings = get_option($this->brute_force_option, [
            'enabled' => '0',
            'attempts' => 5,
            'duration' => 60,
        ]);

        if ($settings['enabled'] !== '1') {
            return;
        }

        $user_ip = $this->get_user_ip();
        $blocked_ips = get_option($this->blocked_ips_option, []);

        $current_time = time();

        if (!isset($blocked_ips[$user_ip])) {
            $blocked_ips[$user_ip] = [
                'attempts' => 1,
                'blocked_until' => 0,
                'attempts_reset_time' => $current_time + (60 * 60), // 1 hora para resetar tentativas
                'log' => [],
            ];
        } else {
            $blocked_ips[$user_ip]['attempts'] += 1;
            // Reseta tentativas se o tempo tiver expirado
            if ($blocked_ips[$user_ip]['attempts_reset_time'] <= $current_time) {
                $blocked_ips[$user_ip]['attempts'] = 1;
                $blocked_ips[$user_ip]['attempts_reset_time'] = $current_time + (60 * 60);
            }
        }

        $blocked_ips[$user_ip]['log'][] = [
            'time' => current_time('Y-m-d H:i:s'),
            'username' => $username,
        ];

        $this->log_event('Tentativa de login falha do IP ' . $user_ip . ' com o usuário "' . $username . '"');

        if ($blocked_ips[$user_ip]['attempts'] >= $settings['attempts']) {
            $blocked_ips[$user_ip]['blocked_until'] = $current_time + ($settings['duration'] * 60);
            $this->log_event('IP bloqueado temporariamente por força bruta: ' . $user_ip);
        }

        update_option($this->blocked_ips_option, $blocked_ips);
    }

    public function check_brute_force_protection($user, $username, $password) {
        $settings = get_option($this->brute_force_option, [
            'enabled' => '0',
            'attempts' => 5,
            'duration' => 60,
        ]);

        if ($settings['enabled'] !== '1') {
            return $user;
        }

        $user_ip = $this->get_user_ip();

        if ($this->is_ip_temporarily_blocked($user_ip)) {
            $this->log_event('Tentativa de login durante bloqueio temporário: ' . $user_ip);
            return new WP_Error('brute_force_blocked', __('Seu IP foi temporariamente bloqueado devido a várias tentativas de login falhadas. Tente novamente mais tarde.'));
        }

        return $user;
    }

    public function is_ip_temporarily_blocked($ip) {
        $blocked_ips = get_option($this->blocked_ips_option, []);
        if (isset($blocked_ips[$ip])) {
            $current_time = time();

            // Se o IP está bloqueado
            if ($blocked_ips[$ip]['blocked_until'] > $current_time) {
                return true;
            }

            // Se o tempo para resetar tentativas expirou, remove o IP da lista
            if ($blocked_ips[$ip]['attempts_reset_time'] <= $current_time) {
                unset($blocked_ips[$ip]);
                update_option($this->blocked_ips_option, $blocked_ips);
                return false;
            }
        }
        return false;
    }

    public function unblock_ip($ip) {
        $blocked_ips = get_option($this->blocked_ips_option, []);
        if (isset($blocked_ips[$ip])) {
            unset($blocked_ips[$ip]);
            update_option($this->blocked_ips_option, $blocked_ips);
            $this->log_event('IP desbloqueado manualmente: ' . $ip);
        }
    }

    public function get_brute_force_log($ip) {
        $blocked_ips = get_option($this->blocked_ips_option, []);
        if (isset($blocked_ips[$ip])) {
            return $blocked_ips[$ip]['log'];
        }
        return [];
    }

    /*** Adicionar IP à Blacklist ***/
    public function add_ip($ip) {
        $blacklisted_ips = get_option($this->blacklist_option, []);
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) && !in_array($ip, $blacklisted_ips)) {
            $blacklisted_ips[] = $ip;
            update_option($this->blacklist_option, array_values($blacklisted_ips));
            $this->log_event('IP adicionado à blacklist: ' . $ip);
            return true;
        }
        return false;
    }

    /*** Remover IP da Blacklist ***/
    public function remove_ip($ip) {
        $blacklisted_ips = get_option($this->blacklist_option, []);
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            $key = array_search($ip, $blacklisted_ips);
            if ($key !== false) {
                unset($blacklisted_ips[$key]);
                update_option($this->blacklist_option, array_values($blacklisted_ips));
                $this->log_event('IP removido da blacklist: ' . $ip);
                return true;
            }
        }
        return false;
    }

    /*** Enviar Email de Reporte ***/
    public function send_report_email($ip, $reason, $brute_force_log = []) {
        $to = 'abuse@dolutech.com';
        $subject = 'Reporte de IP para Blacklist';
        // Monta a mensagem do email
        $message = '
        <html>
        <head>
          <title>Reporte de IP para Blacklist</title>
        </head>
        <body>
          <p>Um novo IP foi reportado para inclusão na blacklist.</p>
          <table>
            <tr>
              <td><strong>IP:</strong></td>
              <td>' . esc_html($ip) . '</td>
            </tr>
            <tr>
              <td><strong>Motivo:</strong></td>
              <td>' . nl2br(esc_html($reason)) . '</td>
            </tr>
          </table>';

        if (!empty($brute_force_log)) {
            $message .= '<h3>Log de Tentativas de Login:</h3><ul>';
            foreach ($brute_force_log as $entry) {
                $message .= '<li>' . esc_html($entry['time']) . ' - Usuário: ' . esc_html($entry['username']) . '</li>';
            }
            $message .= '</ul>';
        }

        $message .= '<br><p>Este email foi enviado pelo Plugin Dolutech Blacklist Security.</p></body></html>';

        $headers = ['Content-Type: text/html; charset=UTF-8'];

        $sent = wp_mail($to, $subject, $message, $headers);
        if ($sent) {
            $this->log_event('IP reportado à Dolutech: ' . $ip);
        } else {
            $this->log_event('Falha ao enviar email para reportar IP: ' . $ip);
        }
        return $sent;
    }

    /*** Logging ***/
    public function log_event($message) {
        $logs = get_option($this->log_option, []);
        $timestamp = current_time('Y-m-d H:i:s');
        $logs[] = "[$timestamp] $message";
        update_option($this->log_option, $logs);
    }

    /*** Enviar Email Diário de Logs ***/
    public function send_daily_log_email() {
        $log_email_address = get_option('dolutech_log_email_address', '');
        $logs = get_option($this->log_option, []);

        if (!empty($log_email_address) && !empty($logs)) {
            $subject = 'Relatório Diário de Logs - Dolutech Blacklist Security';
            // Monta a mensagem do email
            $message = '
            <html>
            <head>
              <title>Relatório Diário de Logs</title>
            </head>
            <body>
              <h2>Relatório Diário de Logs</h2>
              <pre style="background-color:#f8f9fa;padding:15px;">' . esc_html(implode("\n", $logs)) . '</pre>
              <br>
              <p>Este email foi enviado pelo Plugin Dolutech Blacklist Security.</p>
            </body>
            </html>
            ';
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $sent = wp_mail($log_email_address, $subject, $message, $headers);
            if ($sent) {
                $this->log_event('Email diário de logs enviado para ' . $log_email_address);
                // Limpa os logs após o envio
                update_option($this->log_option, []);
            } else {
                $this->log_event('Falha ao enviar email diário de logs para ' . $log_email_address);
            }
        }
    }

}

new Dolutech_Blacklist_Security();
