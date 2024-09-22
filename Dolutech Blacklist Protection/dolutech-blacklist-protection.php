<?php
/*
Plugin Name: Dolutech Blacklist Protection
Description: Bloqueia IPs listados na blacklist da Dolutech.
Version: 0.0.1
Author: Lucas Catão de Moraes
Author URI: https://dolutech.com
License: GPL2
Requires at least: 6.6.0
Requires PHP: 8.3
*/

if (!defined('ABSPATH')) {
    exit; // Sai se acessado diretamente
}

class Dolutech_Blacklist_Protection {

    private $option_name = 'dolutech_blacklist_ips';
    private $blacklist_url = 'https://raw.githubusercontent.com/dolutech/blacklist-dolutech/main/Black-list-semanal-dolutech.txt';
    private $log_option_name = 'dolutech_blacklist_logs';

    public function __construct() {
        add_action('admin_menu', [$this, 'create_plugin_menu']);
        add_action('init', [$this, 'block_blacklisted_ips']);
        register_activation_hook(__FILE__, [$this, 'activate_plugin']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate_plugin']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        add_action('dolutech_daily_update', [$this, 'update_blacklist']);
        add_action('dolutech_daily_log_email', [$this, 'send_daily_log_email']);

        if (!wp_next_scheduled('dolutech_daily_update')) {
            wp_schedule_event(time(), 'daily', 'dolutech_daily_update');
        }

        // Schedule daily log email if enabled
        $log_email_enabled = get_option('dolutech_log_email_enabled', '0');
        if ($log_email_enabled === '1' && !wp_next_scheduled('dolutech_daily_log_email')) {
            wp_schedule_event(time(), 'daily', 'dolutech_daily_log_email');
        }

        // Adiciona a ação para o download dos logs
        add_action('admin_post_dolutech_download_logs', [$this, 'download_logs']);
    }

    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'dolutech-blacklist') === false) {
            return;
        }
        wp_enqueue_style('bootstrap-css', 'https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css');
        wp_enqueue_script('bootstrap-js', 'https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js', ['jquery'], null, true);
    }

    public function create_plugin_menu() {
        add_menu_page(
            'Dolutech Blacklist',
            'Dolutech Blacklist',
            'manage_options',
            'dolutech-blacklist',
            [$this, 'plugin_settings_page'],
            'dashicons-shield',
            81
        );

        add_submenu_page(
            'dolutech-blacklist',
            'Logs',
            'Logs',
            'manage_options',
            'dolutech-blacklist-logs',
            [$this, 'plugin_logs_page']
        );
    }

    /*** Página de Configurações ***/
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

        $blacklist_active = get_option('dolutech_blacklist_active', '1');
        ?>
        <div class="wrap">
            <div class="container mt-4">
                <h1 class="mb-4">Dolutech Blacklist Protection</h1>

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
                            <input type="submit" name="dolutech_add_ip" value="Adicionar IP" class="btn btn-success">
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
                            <input type="submit" name="dolutech_remove_ip" value="Remover IP" class="btn btn-danger">
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

    /*** Página de Logs ***/
    public function plugin_logs_page() {
        // Verifica se o usuário tem permissão
        if (!current_user_can('manage_options')) {
            return;
        }

        $messages = [];

        // Processa as configurações de logs
        if (isset($_POST['dolutech_save_logs_settings']) && check_admin_referer('dolutech_logs_settings_action', 'dolutech_logs_settings_nonce')) {
            $log_email_enabled = isset($_POST['dolutech_log_email_enabled']) ? '1' : '0';
            $log_email_address = sanitize_email($_POST['dolutech_log_email_address']);

            update_option('dolutech_log_email_enabled', $log_email_enabled);
            update_option('dolutech_log_email_address', $log_email_address);

            // Agenda ou remove o agendamento do email diário de logs
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

        $logs = get_option($this->log_option_name, []);

        ?>
        <div class="wrap">
            <div class="container mt-4">
                <h1 class="mb-4">Logs do Dolutech Blacklist Protection</h1>

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
                            <form method="get" action="<?php echo admin_url('admin-post.php'); ?>">
                                <?php wp_nonce_field('dolutech_download_logs_action', 'dolutech_download_logs_nonce'); ?>
                                <input type="hidden" name="action" value="dolutech_download_logs">
                                <input type="submit" name="dolutech_download_logs" value="Baixar Logs em TXT" class="btn btn-secondary">
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

        $logs = get_option($this->log_option_name, []);
        $log_content = implode("\n", $logs);

        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="dolutech_blacklist_logs.txt"');
        echo $log_content;
        exit;
    }

    /*** Ativação e Desativação ***/
    public function activate_plugin() {
        update_option('dolutech_blacklist_active', '1');
        $this->update_blacklist();
    }

    public function deactivate_plugin() {
        delete_option('dolutech_blacklist_active');
        delete_option($this->option_name);
        delete_option($this->log_option_name);
        wp_clear_scheduled_hook('dolutech_daily_update');
        wp_clear_scheduled_hook('dolutech_daily_log_email');
    }

    /*** Atualização da Blacklist ***/
    public function update_blacklist($manual = false) {
        $response = wp_remote_get($this->blacklist_url);
        if (is_wp_error($response)) {
            $this->log_event('Falha ao atualizar a blacklist: ' . $response->get_error_message());
            return;
        }

        $body = wp_remote_retrieve_body($response);
        $ips = explode("\n", $body);
        $ips = array_filter(array_map('trim', $ips));

        // Remove duplicatas e reindexa o array
        $ips = array_values(array_unique($ips));

        update_option($this->option_name, $ips);

        $this->log_event('Blacklist atualizada' . ($manual ? ' manualmente' : '') . '. Total de IPs: ' . count($ips));
    }

    /*** Bloqueio de IPs ***/
    public function block_blacklisted_ips() {
        // Verifica se a blacklist está ativa
        if (get_option('dolutech_blacklist_active', '1') !== '1') {
            return;
        }

        $blacklisted_ips = get_option($this->option_name, []);
        $user_ip = $_SERVER['REMOTE_ADDR'];

        if (in_array($user_ip, $blacklisted_ips)) {
            $this->log_event('Acesso bloqueado para IP: ' . $user_ip);
            status_header(403);
            // Mensagem personalizada
            $message = 'Seu IP encontra-se na Blacklist da Dolutech. Caso acredite que foi um erro, envie um email para <a href="mailto:abuse@dolutech.com">abuse@dolutech.com</a> e informe o motivo.';
            wp_die($message, 'Acesso Bloqueado', ['response' => 403]);
        }
    }

    /*** Remover IP ***/
    public function remove_ip($ip) {
        $blacklisted_ips = get_option($this->option_name, []);
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $key = array_search($ip, $blacklisted_ips);
            if ($key !== false) {
                unset($blacklisted_ips[$key]);
                update_option($this->option_name, array_values($blacklisted_ips));
                $this->log_event('IP removido da blacklist: ' . $ip);
                return true;
            }
        }
        return false;
    }

    /*** Adicionar IP ***/
    public function add_ip($ip) {
        $blacklisted_ips = get_option($this->option_name, []);
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $blacklisted_ips)) {
            $blacklisted_ips[] = $ip;
            update_option($this->option_name, array_values($blacklisted_ips));
            $this->log_event('IP adicionado à blacklist: ' . $ip);
            return true;
        }
        return false;
    }

    /*** Enviar Email de Reporte ***/
    public function send_report_email($ip, $reason) {
        $to = 'abuse@dolutech.com';
        $subject = 'Reporte de IP para Blacklist';
        // Mensagem em HTML com assinatura
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
          </table>
          <br>
          <p>Este email foi enviado pelo Plugin Dolutech Blacklist Protection.</p>
        </body>
        </html>
        ';
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
        $logs = get_option($this->log_option_name, []);
        $timestamp = current_time('Y-m-d H:i:s');
        $logs[] = "[$timestamp] $message";
        update_option($this->log_option_name, $logs);
    }

    /*** Enviar Email Diário de Logs ***/
    public function send_daily_log_email() {
        $log_email_address = get_option('dolutech_log_email_address', '');
        $logs = get_option($this->log_option_name, []);

        if (!empty($log_email_address) && !empty($logs)) {
            $subject = 'Relatório Diário de Logs - Dolutech Blacklist Protection';
            // Mensagem em HTML com assinatura
            $message = '
            <html>
            <head>
              <title>Relatório Diário de Logs</title>
            </head>
            <body>
              <h2>Relatório Diário de Logs</h2>
              <pre style="background-color:#f8f9fa;padding:15px;">' . esc_html(implode("\n", $logs)) . '</pre>
              <br>
              <p>Este email foi enviado pelo Plugin Dolutech Blacklist Protection.</p>
            </body>
            </html>
            ';
            $headers = ['Content-Type: text/html; charset=UTF-8'];

            $sent = wp_mail($log_email_address, $subject, $message, $headers);
            if ($sent) {
                $this->log_event('Email diário de logs enviado para ' . $log_email_address);
                // Limpa os logs após o envio
                update_option($this->log_option_name, []);
            } else {
                $this->log_event('Falha ao enviar email diário de logs para ' . $log_email_address);
            }
        }
    }
}

new Dolutech_Blacklist_Protection();
