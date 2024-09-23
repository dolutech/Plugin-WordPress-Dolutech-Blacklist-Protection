# Dolutech Blacklist Security

**Versão:** 0.1.0  
**Autor:** Lucas Catão de Moraes  
**Licença:** GPL v2.0 or later  
**Requer WordPress:** 6.6.0 ou superior  
**Requer PHP:** 8.3 ou superior  

## Descrição

**Dolutech Blacklist Security** é um plugin avançado de segurança para WordPress que bloqueia IPs maliciosos usando uma blacklist atualizada diariamente pela Dolutech. Além disso, oferece proteção contra ataques de força bruta e suporta a adição de IPs e DDNS à whitelist para evitar bloqueios.

### Funcionalidades

- **Atualização Automática da Blacklist**: A blacklist de IPs maliciosos é atualizada diariamente, automaticamente.
- **Proteção contra Ataques de Força Bruta**: Monitora tentativas de login e bloqueia IPs suspeitos após múltiplas falhas de autenticação.
- **Whitelist de IPs e Suporte para DDNS**: Permite adicionar IPs ou DDNS à whitelist, garantindo que não sejam bloqueados.
- **Logs Detalhados**: Registra tentativas de login e bloqueios de IPs com opção de envio dos logs por email diariamente.
- **Reportar IPs Maliciosos**: Opção de reportar IPs suspeitos para a Dolutech diretamente pelo painel de administração do WordPress.
- **Interface de Administração Simples e Amigável**: Todas as configurações são facilmente gerenciáveis através do painel do WordPress.

### Principais Componentes

- **Blacklist**: O plugin bloqueia IPs maliciosos com base em uma lista atualizada constantemente. A atualização é feita automaticamente todos os dias.
- **Proteção contra Força Bruta**: Bloqueia temporariamente IPs após um número configurável de tentativas de login falhas.
- **Whitelist e DDNS**: Permite adicionar IPs ou domínios DDNS à whitelist, garantindo que esses IPs nunca sejam bloqueados.
- **Logs de Segurança**: Todas as atividades de bloqueio são registradas e podem ser enviadas por email ou baixadas manualmente em formato TXT.
- **Reporte de IPs**: IPs podem ser reportados diretamente para a Dolutech com um motivo, para que sejam investigados e possivelmente adicionados à blacklist global.

## Instalação

1. Faça o download do repositório ou baixe o arquivo ZIP do plugin.
2. Extraia o arquivo ZIP e faça o upload da pasta para o diretório `/wp-content/plugins/` do seu WordPress.
3. No painel de administração do WordPress, vá até "Plugins" e ative o plugin **Dolutech Blacklist Security**.
4. Após a ativação, um novo menu "Dolutech Security" estará disponível no painel de administração para configurar a blacklist e as opções de proteção contra força bruta.

## Atualização Automática da Blacklist

O plugin baixa e atualiza automaticamente a blacklist de IPs maliciosos da Dolutech todos os dias. Caso você precise forçar uma atualização manual, essa opção também está disponível no painel de administração.

## Proteção contra Força Bruta

Ative a proteção contra força bruta para bloquear IPs que tentam realizar várias tentativas de login falhas. O plugin permite configurar quantas tentativas serão permitidas antes de um IP ser temporariamente bloqueado, assim como a duração do bloqueio.

### Configurações de Força Bruta:
- Número de tentativas de login antes do bloqueio.
- Duração do bloqueio (em minutos).
- Logs detalhados das tentativas de login falhas e dos IPs bloqueados.

## Whitelist de IPs e Suporte para DDNS

Adicione seu IP à whitelist para garantir que ele nunca seja bloqueado pelo plugin, ideal para administradores com IPs fixos. Caso você tenha um DDNS, pode adicioná-lo à whitelist, e o plugin atualizará automaticamente o IP vinculado ao DDNS todos os dias.

## Logs e Relatórios

O plugin mantém logs detalhados de todas as tentativas de login e bloqueios de IPs. Esses logs podem ser acessados diretamente pelo painel de administração, enviados por email diariamente ou baixados como um arquivo TXT.

### Opções de Logs:
- Visualize os logs diretamente no painel de administração.
- Baixe os logs em formato TXT.
- Ative o envio diário dos logs para um endereço de email configurado.

## Reporte de IPs Suspeitos

IP suspeito? O plugin permite que você reporte IPs diretamente para a Dolutech, fornecendo um motivo para o reporte. Isso ajuda a manter a blacklist global sempre atualizada e precisa.

## Uso

1. **Ativando a Blacklist:** Após ativar o plugin, a blacklist será atualizada automaticamente. A ativação e desativação podem ser feitas diretamente pelo painel de administração.
2. **Proteção contra Força Bruta:** Ative a proteção contra força bruta na aba dedicada e configure o número de tentativas e a duração do bloqueio.
3. **Gerenciamento de Whitelist e DDNS:** Adicione IPs fixos ou domínios DDNS à whitelist para garantir que não sejam bloqueados.
4. **Logs de Segurança:** Monitore as tentativas de login e bloqueios no seu site diretamente pelo painel ou configure o envio de logs por email.

## Como Contribuir

Contribuições são sempre bem-vindas! Se você encontrar um bug ou tiver uma sugestão para uma nova funcionalidade:

1. Faça um fork deste repositório.
2. Crie um branch para sua feature ou correção de bug (`git checkout -b nova-feature`).
3. Commit suas mudanças (`git commit -am 'Adicionada nova feature'`).
4. Faça um push para o branch (`git push origin nova-feature`).
5. Abra um Pull Request.

## Licença

Este projeto está licenciado sob os termos da **GPLv2 ou superior**. Consulte o arquivo `LICENSE` para mais detalhes.

---

**Dolutech Blacklist Security** é mantido por [Lucas Catão de Moraes](https://dolutech.com). Para mais informações ou suporte, visite [Dolutech](https://dolutech.com) ou envie um email para abuse@dolutech.com.
