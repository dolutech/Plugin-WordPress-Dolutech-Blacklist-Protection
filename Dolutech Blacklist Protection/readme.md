=== Dolutech Blacklist Protection ===
Contributors: Lucas Catão de Moraes
Donate link: https://dolutech.com
Tags: security, blacklist, ip blocking, firewall
Requires at least: 6.6.0
Tested up to: 6.6.0
Requires PHP: 8.3
Stable tag: 0.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Dolutech Blacklist Protection is a security plugin that blocks IPs listed on Dolutech's blacklist from accessing your website. It also allows you to report IPs to Dolutech for further action.

== Description ==

Dolutech Blacklist Protection is a WordPress plugin designed to enhance your website's security by blocking access from malicious IPs listed on Dolutech's regularly updated blacklist. The blacklist is updated automatically on a daily basis and can also be manually updated at any time. 

The plugin provides the following features:
- Automatically blocks access to your website for any IP address listed in Dolutech's blacklist.
- Allows manual addition and removal of IPs from the blacklist.
- Offers an option to report suspicious IPs directly to Dolutech for further investigation.
- Maintains a log of all actions and offers the ability to download logs as a .txt file.
- Option to send daily logs via email.
- Built with security in mind, following WordPress security best practices.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/dolutech-blacklist-protection` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to "Dolutech Blacklist" in your WordPress admin panel to configure the plugin.
4. Customize settings such as activating or deactivating the blacklist, forcing updates, and managing IPs.

== Frequently Asked Questions ==

= How does the blacklist update? =
The blacklist updates automatically every day from Dolutech's maintained blacklist. You can also force an update manually from the plugin settings.

= Can I add or remove IPs manually? =
Yes, you can add IPs to the blacklist manually or remove IPs if you believe they were added by mistake.

= Can I report a suspicious IP to Dolutech? =
Yes, the plugin provides an option to report any IP you add to the blacklist. The report is sent to Dolutech via email.

= Is the plugin secure? =
Yes, the plugin follows WordPress security best practices, including sanitizing user inputs and protecting against CSRF attacks.

= Does the plugin work with other security plugins? =
Yes, Dolutech Blacklist Protection is designed to complement other security plugins. It can be used alongside firewalls, login security, and other WordPress security solutions.

== Screenshots ==

1. Plugin Settings Page: View and manage the status of the blacklist, update manually, and add/remove IPs.
2. Logs Page: View logs of blocked IPs and other actions, and download logs in .txt format.

== Changelog ==

= 0.0.1 =
* Initial release of the plugin.
* Automatically block IPs listed on the Dolutech blacklist.
* Option to manually add or remove IPs.
* Force blacklist update functionality.
* Report IPs to Dolutech for further action.
* Logging and daily email notifications for admins.

== Upgrade Notice ==

= 0.0.1 =
Initial release of Dolutech Blacklist Protection.

== License ==

This plugin is licensed under the GPLv2 or later.
