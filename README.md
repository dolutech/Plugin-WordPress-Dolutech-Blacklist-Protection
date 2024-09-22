# Dolutech Blacklist Protection

**Dolutech Blacklist Protection** é um plugin de segurança para WordPress que bloqueia IPs maliciosos listados na blacklist da Dolutech. O plugin permite bloquear automaticamente IPs abusivos, reportar IPs suspeitos diretamente para a equipe da Dolutech e muito mais.

## Funcionalidades

- **Bloqueio automático de IPs**: Bloqueia qualquer IP listado na blacklist da Dolutech, impedindo o acesso ao site.
- **Atualização automática da blacklist**: A lista de IPs é atualizada diariamente a partir da blacklist mantida pela Dolutech.
- **Atualização manual**: Permite forçar a atualização da blacklist a qualquer momento.
- **Gerenciamento manual de IPs**: Adicione ou remova IPs da blacklist diretamente pela interface do plugin.
- **Reportar IPs**: Possibilidade de reportar um IP diretamente para a equipe da Dolutech com um motivo descritivo.
- **Logs detalhados**: O plugin mantém logs de todas as ações e oferece a opção de baixá-los em formato `.txt`.
- **Envio diário de logs por email**: Configuração opcional para receber relatórios diários por email com os eventos registrados pelo plugin.

## Requisitos

- WordPress 6.6.0 ou superior
- PHP 8.3 ou superior

## Instalação

### Método 1: Instalação Automática pelo WordPress ( Opção ainda não disponível)

1. No painel do WordPress, vá para **Plugins** > **Adicionar Novo**.
2. Pesquise por `Dolutech Blacklist Protection`.
3. Instale e ative o plugin.

### Método 2: Instalação Manual

1. Faça o download do plugin deste repositório.
2. No painel do WordPress, vá para **Plugins** > **Adicionar Novo** e clique em **Fazer upload de plugin**.
3. Selecione o arquivo .zip do plugin e clique em **Instalar agora**.
4. Ative o plugin após a instalação.

## Como Usar

1. Após a ativação, acesse **Dolutech Blacklist** no menu de administração do WordPress.
2. No painel, você pode:
   - Ativar ou desativar a blacklist.
   - Forçar uma atualização da blacklist.
   - Adicionar ou remover IPs da blacklist manualmente.
   - Reportar IPs suspeitos diretamente para a equipe Dolutech.
3. Acesse a aba **Logs** para visualizar as atividades do plugin e baixar logs em formato `.txt`.

## Contribuição

Se você deseja contribuir com este plugin, siga os passos abaixo:

1. Faça um fork do repositório.
2. Crie um branch para suas modificações (`git checkout -b feature/nome-da-feature`).
3. Faça o commit das suas mudanças (`git commit -m 'Adiciona nova funcionalidade X'`).
4. Faça o push para o branch (`git push origin feature/nome-da-feature`).
5. Abra um Pull Request.

## FAQ

### Como o plugin atualiza a blacklist?
A lista de IPs é atualizada automaticamente todos os dias a partir da blacklist mantida pela Dolutech. Você também pode forçar uma atualização manualmente pela interface do plugin.

### Posso adicionar ou remover IPs manualmente?
Sim, você pode adicionar novos IPs à blacklist e remover IPs que foram adicionados por engano.

### Posso reportar um IP diretamente para a Dolutech?
Sim, há uma opção no plugin para reportar IPs adicionados à blacklist. O IP é enviado por email para a equipe da Dolutech para investigação adicional.

### Como configuro o envio de logs por email?
Na aba de **Logs**, você pode inserir um endereço de email para o qual deseja receber os relatórios diários e ativar essa funcionalidade.

## Licença

Este projeto é licenciado sob a licença GPLv2 ou posterior. Consulte o arquivo [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html) para mais detalhes.

---

Desenvolvido por [Lucas Catão de Moraes](https://dolutech.com).
