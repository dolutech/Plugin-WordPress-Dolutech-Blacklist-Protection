=== Dolutech Blacklist Security ===
Contributors: Lucas Catão de Moraes
Donate link: https://dolutech.com
Tags: security, blacklist, brute-force, ddns, protection
Requires at least: 6.6.0
Tested up to: 6.6.0
Requires PHP: 8.3
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Dolutech Blacklist Security é um plugin avançado que bloqueia IPs maliciosos usando uma blacklist atualizada pela Dolutech. Também oferece proteção contra ataques de força bruta e suporte para DDNS.

== Descrição ==

O plugin **Dolutech Blacklist Security** ajuda a proteger o seu site ao bloquear IPs maliciosos com base em uma blacklist atualizada diariamente pela Dolutech. Ele também oferece funcionalidades de proteção contra ataques de força bruta, gerenciando tentativas de login falhas, e permite que o administrador defina IPs e DDNS na whitelist para que nunca sejam bloqueados.

### Funcionalidades principais:
- **Blacklist automática e atualizada diariamente**: O plugin baixa automaticamente a lista de IPs maliciosos e bloqueia acessos indesejados.
- **Proteção contra ataques de força bruta**: Monitora tentativas de login falhas e bloqueia temporariamente IPs suspeitos.
- **Whitelist de IPs e suporte para DDNS**: Permite adicionar seu próprio IP ou DDNS à whitelist para evitar bloqueios.
- **Logs de segurança**: Registra eventos como tentativas de login falhas e IPs bloqueados, com a opção de enviar os logs por email.
- **Configuração simples**: Interface amigável e fácil de configurar.
- **Reportar IPs suspeitos**: Possibilidade de reportar IPs diretamente para a equipe da Dolutech.

### Configurações:
- Definir o número de tentativas de login antes do bloqueio por força bruta.
- Adicionar/remover IPs à blacklist ou whitelist.
- Adicionar DDNS para atualizações automáticas de IP.
- Enviar logs por email ou baixar em formato TXT.
- Bloquear permanentemente IPs suspeitos diretamente da página de logs.

== Instalação ==

1. Faça o upload dos arquivos do plugin para o diretório `/wp-content/plugins/`.
2. Ative o plugin através do menu 'Plugins' no WordPress.
3. Acesse o menu "Dolutech Security" no painel de administração para configurar as opções de blacklist e proteção contra força bruta.

== Atualização Automática da Blacklist ==
O plugin faz o download e atualiza automaticamente a blacklist todos os dias. Se necessário, a atualização pode ser forçada manualmente através da interface de administração.

== Proteção contra Força Bruta ==
Ative a proteção contra força bruta para monitorar tentativas de login suspeitas. IPs que excederem o número de tentativas permitidas serão bloqueados temporariamente. Esses IPs também podem ser adicionados permanentemente à blacklist.

== Logs e Relatórios ==
O plugin mantém logs de eventos de segurança que podem ser visualizados na interface de administração. Você pode baixar os logs ou configurá-los para serem enviados por email diariamente.

== Suporte para DDNS ==
Permite adicionar um endereço DDNS para que o plugin atualize automaticamente o IP na whitelist diariamente.

== Exemplo de uso ==
- Proteja seu site WordPress de IPs maliciosos conhecidos com uma blacklist constantemente atualizada.
- Evite que bots tentem descobrir suas credenciais de login ativando a proteção contra força bruta.
- Use logs detalhados para monitorar eventos de segurança e receber notificações por email.

== Licença ==

Este plugin está licenciado sob a GNU General Public License v2.0 ou superior.

== Changelog ==

= 0.1.0 =
* Primeira versão estável do plugin.
* Implementação da blacklist automática com atualizações diárias.
* Proteção contra ataques de força bruta.
* Suporte para whitelist de IPs e DDNS.
* Funções de logs com envio por email.
* Reporte de IPs suspeitos para a equipe Dolutech.

== Notas Finais ==

Para mais informações ou para relatar problemas de segurança, entre em contato com a Dolutech em https://dolutech.com ou envie um email para abuse@dolutech.com.
