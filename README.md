Relatório de Pentest: Privilege Escalation em Container Linux (Red Hat UBI)

Autor: Marcos Leal Data: 01 de Janeiro de 2026 Tipo: CTF / Laboratório Educacional / Red Hat Sandbox
1. Sumário Executivo

Durante a análise de segurança de um ambiente containerizado, foi identificada uma falha crítica de configuração nas permissões de ficheiros do sistema e na gestão de grupos de utilizadores.

Um utilizador comum, pertencente indevidamente ao grupo root (GID 0), conseguiu explorar permissões de escrita no ficheiro /etc/passwd para criar uma conta de superutilizador (backdoor), obtendo controlo total do sistema (Privilégio Máximo). A vulnerabilidade permitiu contornar controlos de segurança adicionais, como SELinux e Linux Capabilities restritas.
2. Análise Técnica (Passo a Passo)
Fase 1: Reconhecimento e Enumeração (Reconnaissance)

O acesso inicial foi obtido através de um shell restrito. A primeira etapa consistiu em identificar o ambiente e as permissões do utilizador atual.

O comando id revelou uma configuração perigosa:

    [FOTO AQUI: Screenshot do comando id mostrando "gid=0(root)" e "groups=0(root)"]

Análise: O utilizador atual (user), apesar de ter um UID alto (não privilegiado), pertence ao grupo GID 0 (root). Esta é uma configuração comum em ambientes OpenShift/Kubernetes para facilitar permissões de ficheiros, mas apresenta riscos elevados se não for devidamente isolada.

De seguida, verificaram-se as permissões de ficheiros críticos. O comando ls -l /etc/passwd revelou a vulnerabilidade chave:

    [FOTO AQUI: Screenshot do comando ls -l /etc/passwd destacando as permissões -rw-rw-r--]

Vulnerabilidade Identificada: O ficheiro /etc/passwd tem permissões de escrita para o grupo (rw-). Como o nosso utilizador pertence a esse grupo (GID 0), temos permissão legítima para alterar a lista de utilizadores do sistema.
Fase 2: Tentativas de Exploração (Falha e Adaptação)

Inicialmente, tentou-se uma abordagem via User Namespaces e injeção em scripts de inicialização (entrypoint.sh).

    Ação: Criação de um script Python para mapear o utilizador para nobody e modificar o script de arranque.

    Resultado: Sucesso na injeção, mas falha na persistência. O container era "stateless" (sem estado), e ao forçar o reinício, as alterações no disco foram perdidas.

    Lição Aprendida: Em ambientes efémeros, a exploração deve ser imediata (runtime) e não depender de reinicializações.

Fase 3: Exploração Bem-Sucedida (Exploitation)

Mudou-se o foco para a exploração direta da vulnerabilidade de permissão no /etc/passwd em tempo real.

Ação: Injeção de um utilizador "root" alternativo. Criámos um utilizador chamado toor com UID 0 (o mesmo ID do root) e definimos o campo de senha como vazio (::). Esta técnica contorna a necessidade de crackear hashes complexos no /etc/shadow, pois o sistema assume que este utilizador não requer senha.

A imagem abaixo demonstra a injeção do utilizador e a mudança imediata para a conta de superutilizador:

    [FOTO AQUI: Screenshot mostrando os comandos: echo "toor::0..." >> /etc/passwd, seguido de su toor e o id final mostrando uid=0(root)]

Estado: Acesso Root confirmado. O prompt mudou de $ para #.
Fase 4: Pós-Exploração e Persistência

Para garantir o acesso futuro sem depender do utilizador toor (que é facilmente detetável numa auditoria), foi criado um binário SUID (Set User ID) como backdoor.

Ação: Cópia do binário do Bash e ativação do bit SUID.

    [FOTO AQUI: Screenshot dos comandos cp /bin/bash ... e chmod +s ..., seguido de um ls -l mostrando o ficheiro com a permissão rwsr-xr-x (geralmente destacado a vermelho)]

Resultado: Qualquer execução futura deste binário com a flag -p concede privilégios de root (euid=0), mesmo que o atacante tenha regressado ao utilizador comum, garantindo persistência no ambiente.
Fase 5: Análise de Defesas (Container Hardening)

Durante a pós-exploração, verificou-se que o ambiente possuía camadas de defesa adicionais (Defense in Depth). Mesmo com UID 0, algumas ações de sistema foram bloqueadas:

    Leitura de /etc/shadow: Retornou Permission denied.

    Comando chown (mudar dono de ficheiro): Retornou Operation not permitted.

    [FOTO AQUI: Screenshot tentando ler o /etc/shadow e falhando, comprovando as restrições do container]

Conclusão da Análise: O container está protegido por Linux Capabilities restritas (o runtime removeu capacidades como CAP_CHOWN e CAP_DAC_READ_SEARCH) e provavelmente um perfil SELinux restritivo. No entanto, a capacidade de escrever no /etc/passwd foi um vetor de ataque suficiente para comprometer a integridade do sistema, contornando a proteção do /etc/shadow.
3. Remediação (Mitigação)

Para corrigir esta falha, recomenda-se:

    Remediação Imediata: Remover a permissão de escrita do grupo no ficheiro de configuração crítica:
    Bash

    chmod 644 /etc/passwd

    Princípio do Menor Privilégio (PoLP): Remover utilizadores não-administrativos do grupo root (GID 0). O acesso a ficheiros partilhados deve ser gerido por grupos específicos, não pelo GID 0.

    Hardening de Container: Implementar políticas de segurança (SecurityContext em Kubernetes/OpenShift) para impor sistemas de ficheiros raiz como "Read-Only", impedindo qualquer modificação em ficheiros de sistema.

4. Conclusão e Parecer Final

O presente teste de intrusão evidenciou que a segurança de contentores não depende exclusivamente da imagem base ou do kernel, mas sim de uma configuração rigorosa de permissões locais.

A vulnerabilidade explorada (Escalação de Privilégios via Misconfiguration) foi classificada como CRÍTICA. A combinação de um utilizador padrão pertencente ao grupo root (GID 0) com permissões de escrita excessivas no /etc/passwd criou um vetor de ataque trivial, porém devastador.

Este exercício reforça a máxima da cibersegurança: "Defesa em Profundidade" (Defense in Depth). Uma única camada de falha (permissão de arquivo) foi suficiente para quebrar o perímetro de segurança do contentor, tornando ineficazes as outras camadas de defesa (como SELinux) para impedir a tomada de controlo.

Nota: Após a validação da prova de conceito, todas as alterações (utilizador 'toor' e backdoor SUID) foram removidas para restaurar o estado original do laboratório.
