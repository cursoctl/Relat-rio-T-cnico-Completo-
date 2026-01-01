# Relatório Técnico: Privilege Escalation em Container Linux (Red Hat UBI)

**Autor:** Marcos Leal  
**Data:** 01 de janeiro de 2026  
**Tipo:** CTF / Laboratório Educacional / Red Hat Sandbox  
**Classificação:** **CRÍTICA**

---

## 1. Sumário Executivo

Durante a análise de segurança de um ambiente containerizado baseado em **Red Hat Universal Base Image (RHEL UBI)**, foi identificada uma falha crítica de configuração (*misconfiguration*).

Um utilizador comum, pertencente indevidamente ao grupo **root (GID 0)**, conseguiu explorar permissões de escrita excessivas no ficheiro **/etc/passwd**. Essa condição permitiu a criação de uma conta de superutilizador (*backdoor*), resultando na obtenção de **controlo total do sistema (privilégio máximo)**, contornando defesas modernas como **SELinux** e restrições de **Linux Capabilities**.

---

## 2. Análise Técnica (Passo a Passo)

### 2.1 Fase 1 – Reconhecimento e Enumeração

O acesso inicial foi obtido através de um *shell* restrito. A primeira etapa consistiu na identificação do contexto de execução e das permissões atribuídas ao utilizador corrente.

**Comando executado:**

```bash
id
```

**Resultado:**

![Resultado do comando id](user1.png)

**Análise:**
O utilizador atual (`user`), apesar de possuir um UID elevado (não privilegiado), pertence ao grupo **GID 0 (root)**. Esta configuração é relativamente comum em ambientes OpenShift, porém representa um risco elevado quando combinada com permissões inadequadas em ficheiros sensíveis.

**Verificação de ficheiros críticos:**

```bash
ls -l /etc/passwd
```

**Vulnerabilidade identificada:**
O ficheiro **/etc/passwd** apresenta permissões de escrita para o grupo (`rw-`). Como o utilizador pertence a esse grupo, torna-se possível modificar diretamente a base de dados de utilizadores do sistema.

![Permissões inseguras em /etc/passwd](Recon.png)

---

### 2.2 Fase 2 – Tentativas e Metodologia

Inicialmente, foi testada a exploração via *User Namespaces*, com o objetivo de injetar código em scripts de inicialização (*entrypoint*). Embora a injeção tenha sido bem-sucedida, verificou-se que o container operava de forma **stateless**, revertendo todas as alterações após o reinício.

**Decisão tática:**
Abandonar abordagens dependentes de persistência em disco e concentrar a exploração em **tempo de execução (*runtime exploitation*)**.

---

### 2.3 Fase 3 – Exploração Bem-Sucedida

A exploração concentrou-se na modificação direta do ficheiro **/etc/passwd**, com o objetivo de criar um utilizador alternativo com privilégios administrativos.

**Ação executada:**
Criação do utilizador `toor` com **UID 0** e campo de palavra-passe vazio.

```bash
echo "toor::0:0:root:/root:/bin/bash" >> /etc/passwd
su toor
```

**Resultado:**
A elevação de privilégios ocorreu de forma imediata, sem necessidade de autenticação adicional.

![Exploração via utilizador toor](ataque_toor.png)

---

### 2.4 Fase 4 – Persistência (Backdoor SUID)

Para garantir acesso privilegiado sem depender da conta `toor` (facilmente detetável), foi criado um binário **SUID** a partir do Bash.

**Comandos executados:**

```bash
cp /bin/bash /projects/rootbash
chmod +s /projects/rootbash
```

![Criação do binário SUID](backdoor.png)

**Validação:**
A execução do binário concede privilégios efetivos de root (**euid=0**).

![Execução do backdoor SUID](backdorr-1.png)

---

### 2.5 Fase 5 – Análise de Defesas (Container Hardening)

Mesmo após a obtenção de acesso root, foram observadas camadas de defesa ativas no ambiente:

* Leitura do ficheiro **/etc/shadow** bloqueada (*Permission denied*);
* Alteração de donos de ficheiros (`chown`) impedida (*Operation not permitted*).

**Conclusão técnica:**
O container utiliza **Linux Capabilities** restritas (ausência de `CAP_CHOWN`) e, possivelmente, políticas **SELinux** ativas. Contudo, a permissão incorreta no **/etc/passwd** foi suficiente para comprometer a integridade do sistema, neutralizando essas defesas.

---

## 3. Remediação (Mitigação)

Para corrigir a vulnerabilidade identificada e prevenir explorações semelhantes, recomenda-se:

* **Correção imediata de permissões (crítico):**

```bash
chmod 644 /etc/passwd
```

* **Princípio do Menor Privilégio (PoLP):** Remoção de utilizadores não administrativos do grupo **root (GID 0)**;
* **Imutabilidade:** Configuração do sistema de ficheiros raiz como **read-only** através de políticas de segurança do Kubernetes/OpenShift.

---

## 4. Conclusão e Considerações Éticas

Este teste de intrusão demonstrou que a segurança em containers depende diretamente de uma aplicação rigorosa do conceito de **Defesa em Profundidade**. A falha de uma única camada — neste caso, permissões de ficheiros — foi suficiente para comprometer todo o ambiente.

**Nota ética:**
O teste foi realizado exclusivamente em ambiente isolado (*Red Hat Sandbox*). Após a validação da prova de conceito, todas as alterações introduzidas (utilizadores e binários) foram removidas, restaurando o sistema ao seu estado original.
