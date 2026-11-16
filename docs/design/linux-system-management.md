# SRX: construção de sistemas Linux, kernel, boot e armazenamento

**Estado:** documento de arquitetura e roteiro de implementação. Além dos incrementos
registrados abaixo, os contratos, tipos e comandos propostos aguardam implementação.
**Referência do estudo:** 21 de outubro de 2026.
**Repositório:** `syrox`; executável: `srx`.

**Primeiro incremento implementado:** o tipo público `Os` foi renomeado para
`Services`, o planejamento usa `PlanConsumerKind::Services` e os comandos de
serviços usam `srx services`. Perfis, journals e protocolos persistidos mantêm
seus formatos e identidades. A [migração](../migrations/services.md) descreve a
atualização de projetos e locks. As demais etapas permanecem propostas; as
referências ao `Os` atual abaixo descrevem a base do estudo anterior à migração.

**Fundações de artefatos implementadas:** o módulo
[`store::chunked`](../../crates/syrox-engine/src/store/chunked.rs) admite e
reabre fluxos por chunks de 4 MiB com manifest v1, identidade do conteúdo completo
e verificação limitada em memória. Handles e roots retêm o conjunto completo de
objetos usando os contratos atuais de retenção, recuperação e GC. O
[contrato do formato](../artifacts.md#large-streams-in-the-engine-store) descreve
limites e garantias. A admissão explícita de outputs de sistema usa budgets e resultados v3 com
bundles v2 e materialização por streaming. A integração de workers, receipts,
perfil de execução e CLI ainda está pendente; os limites comuns permanecem.

As interfaces incluem escrita por streaming com finalização verificada e um
reader com seek e cache de um chunk. A geração de initramfs já usa a escrita
direta na Store; índices de outputs grandes poderão usar o reader sem carregar
o artefato inteiro em memória.

A preparação das fontes gerenciadas agora mantém um descritor autenticado e
retenção granular, revalida identidade/metadados e copia por streaming com hash,
limite e EOF antes da publicação atômica. A inspeção do worker também verifica a
fonte sem coletar seu conteúdo inteiro. Cem testes do fluxo gerenciado passaram,
além de um build real com binutils já produzido por fontes e execução do novo
resultado. Os envelopes, formatos e limites comuns continuam preservados; o
perfil completo de sistema permanece pendente.

**Inventário implementado:** `srx system inspect [--json]` observa o kernel,
firmware, presença do device KVM, dispositivos de bloco, identidades, geometria,
partições, holders/slaves e mounts do namespace atual. A biblioteca
[`syrox-system`](../../crates/syrox-system/src/lib.rs) é compartilhável com o
helper sem depender da linguagem ou do builder. A inspeção não abre dispositivos
de bloco, não executa utilitários e não cria configuração ou Store.

**Primitivas de loop verificadas em VM:** a biblioteca configura apenas imagens
regulares privadas com identidade e tamanho revalidados, geometria fixa e
AUTOCLEAR. Um executável Rust passou em Fedora CoreOS fixado, iniciado por
QEMU/OVMF e disco com TCG: escrita limitada, alterações de metadados, liberação
adiada e nova tentativa após desligamento foram observadas. Não houve rede,
disco físico ou alteração do boot do host. O [ambiente e as evidências](../test-tools.md#disposable-loop-device-guest)
estão registrados. A primitiva de montagem ext4 destacada também passou na VM:
limites de armazenamento e inodes, liberação adiada por um descritor da raiz e
verificação final com e2fsck foram observados. A integração do worker sem privilégios e
o enforcement das demais dimensões do orçamento continuam pendentes. O estado
não confunde ENXIO durante rundown com remoção concluída.

**Execução isolada de ferramentas verificada:** mke2fs/e2fsck estáticos e
autenticados executaram em namespaces privados, por memfds selados, com raiz
somente leitura, capabilities zeradas e filtro de syscalls. Um probe verificou
descritores herdados, caminhos, limites e recusas de operações; os checks ext4
antes/depois, esgotamento e liberação passaram na VM. O
[registro da qualificação](../test-tools.md#isolated-ext4-tools) distingue as
tentativas anteriores e o escopo observado. O executável separado
[`syrox-system-helper`](../system-helper.md) já implementa política do
administrador, autenticação do peer e ciclo de scratch privado com journal.
Sua integração com cliente UID/GID 1000 passou na VM: handoff e escrita sem root,
liberação verificada, recusa sem efeitos de pedidos inválidos, preservação em
replay e bloqueio de nova formatação após desconexão incerta. Recuperação após
reset, integração do worker e provisionamento permanecem pendentes. O protocolo
do helper agora oferece inspeção e reconciliação explícitas do scratch no mesmo
boot, vinculadas ao hash das evidências. Ele preserva a imagem, bloqueia sessão
ainda viva, ferramenta sem resultado ou loop ativo e distingue reconciliação de
saúde verificada. Oito testes locais e 19 cenários em VM passaram, incluindo
journal alterado, reconciliação com imagem preservada e descritor retido pelo
cliente. Isso ainda não constitui evidência de recuperação após reset.

A recepção/anexação do scratch também está implementada na biblioteca. Um
processo UID/GID 1000 moveu o mount por descritores para seu namespace privado,
removeu suas capabilities e escreveu no ext4; o helper verificou a liberação e
o filesystem ao final. A repetição usando `ReceivedScratch` passou nos 20
cenários da VM, com binários e hashes separados dos probes anteriores. Ainda
faltam a ligação ao worker de build e o enforcement do orçamento completo.

O gerador puro de ativação do helper pelo systemd também foi implementado. Uma
nova VM passou nos 24 cenários, incluindo socket seqpacket com fd 3, cliente sem
root, valores reais dos limites do cgroup, recusa de acesso ao disco virtual da
VM e recusa de escrita fora do estado autorizado. O teste usou units instaladas
somente no guest. Esses limites são do helper; o perfil e a configuração do
builder de sistema ainda precisam ser conectados.

O cliente tipado do helper e `srx system recover` também passaram numa VM nova,
com 29 cenários. O coordenador autentica o peer root e os recibos selados, mantém
o controle fora do namespace do worker e transfere apenas a raiz do scratch.
A CLI inspeciona uma operação explícita sem efeitos e reconcilia somente o hash
autorizado; hash incorreto foi recusado e os bytes da imagem foram preservados.
Essa recuperação é de scratch privado no mesmo boot. Integração do worker de
build, recuperação após reset e de gerações completas continuam pendentes.

**Observação de filesystem e quotas implementada:** a biblioteca compartilhada
consulta capacidade, inodes, projeto herdado, accounting, enforcement e limites
por descritor. A consulta fixa `FS_IOC_GETFSUUID` acrescenta o UUID externo como
observação suplementar, sem mudar o fingerprint existente ou conferir ownership.
`srx system inspect --builder-directory PATH [--json]` expõe essas
observações sem criar diretórios ou alterar quotas. Ausência de suporte ou
privilégio é explícita. O [contrato dos builders](../system-builders.md) separa
essa evidência da preparação e execução ainda pendentes.

**Primitivas compartilhadas e importação offline implementadas:** o engine
reutiliza a biblioteca de descritores para caminhos restritos, locks e transporte
de FDs e snapshots selados de credenciais, preservando o protocolo, limite de
64 KiB e verificações de identidade existentes.
`srx project import-source` admite um arquivo explicitamente selecionado contra
o SHA e limite da fonte no projeto autenticado, sem alterar URL ou lock. O
[contrato de importação](../source-import.md) descreve validação e retenção.
O catálogo recebeu uma receita experimental de e2fsprogs estático com semente
host explícita. Um build nativo pelo SRX, a criação/verificação de uma imagem
ext4 regular de 64 MiB no sandbox e a execução das três ferramentas pelo runtime
foram realizados. O resultado retém fonte, inventário da semente, action,
artefato e receipt. As ferramentas também foram executadas na qualificação
da primitiva ext4 montada em VM. Isso não qualifica uma toolchain própria,
executor de sistemas ou provisionamento; essas integrações continuam pendentes.

**Contratos de orçamento e armazenamento implementados:** a mesma biblioteca
valida solicitações de recursos contra limites explícitos do administrador e
observações de capacidade, e planeja grafos GPT/ESP, RAID1/10, LUKS2, LVM,
filesystems e mounts. O grafo resolve discos por WWID/serial, rejeita alvos
ambíguos, uso observado, ciclos, sobreposição, composições incompatíveis e
overcommit. A CLI `srx system plan PROJECT#OUTPUT` conecta as declarações
autenticadas ao inventário, compara os sysctls solicitados e tenta resolver os
discos. Distingue binding não resolvido, provisionamento destrutivo, reboot de
geração e restauração de parâmetro ainda não verificada. O relatório identifica
os namespaces atuais e mantém `can_apply: false`; seu hash registra evidência,
sem autorizar escrita. O novo perfil de execução de sistema e a aplicação
privilegiada ainda precisam ser implementados. Esses contratos e observações
não constituem qualificação das pilhas de armazenamento.

**Composição e initramfs implementados na biblioteca:** árvores com produtores,
ownership, permissões e links explícitos são validadas e versionadas. O escritor
`newc` verifica arquivos por streaming; o engine consome outputs autenticados,
admite o arquivo em chunks e retém árvore, proveniência e fontes. O
[contrato de imagens](../system-images.md) registra limites e verificações.
Ainda não há kernel/PID 1 próprios, UKI ou boot de sistema qualificado.

**Árvore dm-verity implementada na biblioteca:** o escritor Rust emite formato
1 com SHA-256, blocos de 4 KiB, salt explícito e níveis em ordem de raiz.
O engine gera níveis por streaming na Store e retém dados, árvore e parâmetros.
Uma comparação com `veritysetup` fixado verificou bytes e raiz em sete tamanhos,
incluindo transições de níveis e o caso de um bloco sem árvore. Essa evidência
é de formato em userspace; ativação no kernel, assinatura da UKI e boot continuam
pendentes. O [contrato de imagens](../system-images.md#dm-verity-hash-devices)
define limites e retenção.

**Declarações de sistema implementadas:** a std oferece `System` e
`HostConfiguration`, projetados separadamente dos consumers de serviços. O
planejador valida referências a outputs, budgets, papéis A/B/ESP, estrutura de
armazenamento, identidade, exposições, serviços/saúde e seleções de kernel/host.
O [contrato das declarações](../system-declarations.md) descreve o uso e as
verificações ainda pendentes, incluindo Kconfig upstream e aplicação privilegiada.
As projeções tipadas preservam opções Kconfig, identidade/usuários, referências
de credenciais, boot, saúde e compatibilidade dos dados persistentes para os
construtores e executores posteriores.

**Bootstrap de binutils exercitado:** o catálogo constrói as ferramentas 2.47
para `x86_64-srx-linux-gnu` a partir da fonte upstream autenticada, com semente
host explícita. Nove executáveis passaram pela inspeção ELF estática. Um segundo
build gerenciado consumiu esse output, montou/ligou/executou uma fonte assembly
fixada com `toolchain none` e produziu um bundle executado offline. Os receipts
retêm a dependência da semente original; compilador, sysroot e cadeia Rust
próprios ainda precisam ser construídos e qualificados.

**Bootstrap de make exercitado:** GNU make 4.4.1 foi construído com semente
explícita e orçamento Standard inalterado. Um consumer gerenciado usou make e
binutils produzidos das fontes para gerar assembly, ligar e executar o resultado,
com `toolchain none`; seu bundle também passou no runtime offline. A assinatura
histórica do make reporta `EXPKEYSIG`, com validade criptográfica registrada:
a política temporal de admissão permanece uma pendência de qualificação e essa
receita está fora da matriz de publicação. O catálogo registra identidades,
limites e essa restrição nas evidências de desenvolvimento.

**Escritor RAW/GPT implementado na biblioteca:** layouts validados recebem
imagens de partições com SHA e tamanho explícitos e geram MBR protetor, GPT
primária/secundária, payloads e preenchimento determinístico por streaming.
O engine publica chunks e manifest somente após verificar os inputs e retém a
união dos objetos. `sfdisk` fixado reconheceu imagens regulares com setores de
512/4096 bytes e a cópia secundária após corrupção da primária. Essa evidência
estabelece interoperabilidade GPT em userspace; ainda não representa rootfs, ESP ou disco
inicializável. O [contrato de imagens](../system-images.md#gpt-raw-disk-images)
registra os limites e o trabalho restante.

**Conversão qcow2 implementada na biblioteca:** um escritor Rust gera qcow2 v3
autocontido, por streaming, com clusters de 64 KiB e refcounts de 16 bits.
O engine consome `BuiltRaw`, retém sua proveniência e as partições transitivas,
e publica a conversão somente após verificar comprimento e SHA. Uma fixture
assinada de `qemu-img` foi preparada no workspace, sem instalar pacotes no host.
Os testes verificam refcounts e comparam a conversão de volta para RAW; a fixture
ainda depende de bibliotecas do host e não qualifica o ambiente de boot.
O [contrato](../system-images.md#standalone-qcow2) e os
[inputs de teste](../test-tools.md) registram essas distinções.

**Preparação de componentes System implementada:** o engine verifica a pertença
do componente à closure do System autenticado, sua receita, fonte, worker e
inputs, incluindo resultados v3. A nova action v1 registra orçamento, política,
limite de fonte e protocolos próprios; não entra no parser v5 comum. A retenção
granular permite GC e preserva inputs cujos roots foram retirados. O adaptador
de limites deriva propriedades finitas de systemd do orçamento da action e
permite observar o contrato completo da unidade. O
[contrato dos builders](../system-builders.md#prepare-a-system-component-and-its-action)
separa essa preparação de execução, scratch, settlement e receipts de sistema,
que ainda precisam ser integrados. A solicitação explícita de scratch também
foi ligada à action e à retenção dos inputs: o controle fica no coordenador,
somente a raiz pode ser duplicada e a liberação requer checks independentes do
helper. Essa ligação passou na VM descartável `v10`, com 33 cenários, escrita
por descritor, GC mantendo a fonte e liberação com filesystem e loop verificados.
Isso ainda não inicia um worker nem qualifica o executor completo.
Os limites dos builds comuns permanecem.

**Inputs grandes por descritores implementados:** a preparação de System exporta
manifest e chunks CAS deduplicados sob um limite explícito de FDs. O novo reader
verifica papéis, metadados, hashes dos chunks e hash lógico completo, oferece seek
com um único cache de 4 MiB e não usa caminhos da Store. Um fluxo real de 1 GiB +
17 bytes passou com quatro descritores; o caso de input v3 também passou depois
da retirada do root por GC. O transporte autenticado, retenção do receptor e
pacote de recursos do novo worker ainda precisam ser conectados. Isso não muda
o formato dos manifests nem faz o worker comum aceitar inputs v3.

**Handoff completo de inputs implementado:** a preparação conta os FDs de todos
os inputs e a reserva do executor antes de criar retenção adicional. O pacote
versionado inclui views, artefatos comuns/chunked e uma descrição de retenção
independente. O receptor verifica hash/metadados, referências e conteúdo, adquire
o lock do interesse e preserva a custódia após a saída do remetente e retirada
dos roots por GC. O transporte seqpacket separado valida credenciais do kernel,
nonce, hashes, offsets e lotes antes de confirmar o recebimento. Um teste entre
processos passou com 33 inputs mistos e 84 descritores, mantendo os dados após
GC no pai. Ainda faltam a ligação à identidade executável/manager, FDSTORE,
workspace gravável, gate, settlement e receipts para um executor System completo.

**Volumes de trabalho e saída separados implementados:** o layout deriva dois
filesystems ext4 do mesmo orçamento admitido e divide o teto global de inodes
proporcionalmente aos bytes. A saída pode ser maior que o scratch sem forjar uma
nova admissão. As primitivas verificam identidades distintas, papéis dos
descritores, geometria, ownership e alvos antes de anexar os mounts. Em 2 de
novembro de 2026, a VM QEMU/OVMF passou pelos 33 casos anteriores e dez novos:
scratch de 64 MiB, saída de 128 MiB, 1.008 inodes efetivos dentro do teto de 1.024,
esgotamento separado, worker UID/GID 1000 sem capabilities após attachment e
liberação independente dos loops, seguida de duas verificações ext4. A fixture
`tests/fixtures/system-build/system-workspace-vm.json` registra pins e evidência.
Essa primeira qualificação utilizou o protocolo anterior de scratch único para
os testes do helper e exercitou o par de volumes diretamente pelas primitivas.
Capacidade do filesystem limita espaço alocado; comprimentos
lógicos de arquivos sparse exigem limites e validação de resultados separados.

**Workspace do componente e helper de dois volumes implementados:** operações
separadas de preparação, liberação, inspeção e recuperação agora mantêm as duas
imagens num único journal. A política root admite o mesmo pedido independentemente
da política do coordenador. A liberação exige teardown dos dois loops e duas
verificações finais; a reconciliação no mesmo boot preserva as imagens e não
afirma saúde do filesystem. `SystemBuildInputs::prepare_workspace` mantém a
custódia dos inputs durante a concessão e revalida os dois papéis antes de exportar
FDs. A VM `v14` passou por 59 casos distintos, incluindo preparação real de um
componente declarado, escrita/fsync nos dois volumes, GC, revalidação dos inputs
e liberação sem criar um build ou receipt. Também verificou recusa de orçamento,
hash incorreto, desconexão e descritor retido bloqueando recuperação. Os dois
ensaios anteriores sem qualificação permanecem registrados separadamente.
`tests/fixtures/system-build/system-workspace-rpc-vm.json` contém pins, escopo e
evidência. Ainda faltam gate e custódia no manager/FDSTORE, execução das receitas,
enforcement completo e receipts de System.

**Recuperação de workspace pela CLI implementada:** `srx system recover` exige
exatamente um seletor, `--scratch-operation` ou `--workspace-operation`, além do
socket explícito. A VM `v15` passou pelos 59 casos anteriores e cinco novos da
CLI: abandono, inspeção, hash incorreto, reconciliação autorizada e estado
terminal. Os hashes das duas imagens foram preservados; a recuperação não
afirmou saúde do filesystem. A fixture
`tests/fixtures/system-build/system-workspace-cli-vm.json` registra os 64 casos,
os binários e o encerramento normal. Não há fallback entre os tipos de operação,
reboot automático, recuperação de gerações nem execução de receitas neste fluxo.

**Extração de fontes grandes de System implementada:** um envelope separado
deriva expansão, arquivo individual e entradas da geometria/inodes do scratch
admitido; o transporte compactado mantém o teto de blob de 1 GiB. O reader usa
offsets próprios e detecta mudança de comprimento. Inspeção e extração compartilham
o parser seguro; os limites e subsets dos perfis comuns permanecem. A inspeção
dos inputs preparados verifica o pin antes/depois e não cria build nem chama o
helper. Passaram 28 testes, além do subprocesso com 1 GiB + 17 bytes sob limite
de endereço de 256 MiB; 65.537 entradas também passaram no caminho System e foram
recusadas pelo limite comum. A evidência nativa está em
`tests/fixtures/system-build/native-system-source-archive.json`. Ainda é necessário
selecionar esse caminho na entrada e no namespace autorizados do worker System;
o ensaio não executa receita nem qualifica o perfil completo.

## 1. Objetivo

Expandir o SRX para atender dois usos:

1. Construir um sistema Linux completo a partir de fontes e gerar imagens inicializáveis.
2. Gerenciar recursos selecionados de instalações Linux existentes.

O usuário deverá conseguir declarar kernel, parâmetros, módulos, boot,
armazenamento e serviços em `.srx`, verificar os tipos, inspecionar um plano e
autorizar sua aplicação.

O objetivo inclui tornar visíveis as consequências das mudanças. O plano precisa
distinguir uma alteração reversível de configuração, uma mudança que exige reboot
e uma operação que destrói dados.

A primeira entrega completa será qualificada em VMs descartáveis. O suporte a
hardware real virá depois dessa qualificação.

## 2. Decisões estabelecidas

| Área | Decisão |
|---|---|
| Construção do sistema | Componentes distribuídos construídos pelo SRX a partir de fontes |
| Bootstrap | Toolchain gerenciada própria antes da construção da base |
| Atualização do sistema completo | Gerações imutáveis |
| Primeiro ambiente | VM descartável |
| Arquitetura inicial | Linux x86_64 |
| Firmware e boot | UEFI e systemd-boot |
| Perfil inicial | Console, rede e SSH |
| Segurança inicial | Secure Boot e LUKS2 |
| Filesystem inicial | ext4 |
| Gerenciamento de volumes | LVM |
| RAID inicial | RAID1 e RAID10 |
| Adoção de instalações existentes | Arch, Debian e Ubuntu |
| Compatibilidade de APIs | Breaking changes permitidos, com migração documentada |
| TPM2 e desktop | Etapas posteriores |

Essas decisões definem um Linux mínimo funcional. A expansão para desktop, outras
arquiteturas e outras pilhas de armazenamento será construída sobre essa base.

## 3. Estado atual do projeto

O SRX já fornece partes importantes da fundação:

- Linguagem tipada, módulos e configuração declarativa.
- Autenticação de projetos, assets e biblioteca padrão.
- Locks e aquisição de fontes com identidade explícita.
- Receitas, dependências e execução de builds.
- Store com verificação de conteúdo, retenção e recuperação.
- Planejamento anterior aos efeitos.
- Execução de aplicações com suas dependências.
- Preparação e aplicação de gerações de serviços.
- Integração com systemd e observação de capacidades do Linux.
- Journal e recuperação de operações interrompidas.

O `Os` atual contém pacotes e serviços. Ele opera sobre um Linux existente e não
representa uma instalação completa com kernel, boot e discos. Os contratos atuais
estão descritos em [perfis de instalação](../os-profiles.md) e
[seleção de artefatos](../artifacts.md).

Os perfis atuais também exigem uma identidade de execução sem root. Essa restrição
deve continuar protegendo o fluxo de serviços e builds. A nova autoridade de
sistema será uma capacidade separada.

Existem limitações concretas para construir sistemas maiores:

| Limite atual | Valor |
|---|---:|
| Fonte compactada no perfil Large | 32 MiB |
| Fonte Raw no perfil Large | 128 MiB |
| Saída individual | 128 MiB |
| Resultado agregado | 512 MiB |
| Blob individual no Store | 1 GiB |
| Duração máxima de build | 30 minutos |
| Scratch do perfil Large | Aproximadamente 1 GiB em tmpfs |

Esses limites foram conferidos em
[`build`](../../crates/syrox-engine/src/build/mod.rs),
[`BuildProgram`](../../crates/syrox-engine/src/build/program.rs),
[`artifact`](../../crates/syrox-engine/src/result/artifact.rs),
[`result`](../../crates/syrox-engine/src/result/mod.rs) e
[`store`](../../crates/syrox-engine/src/store/mod.rs). A restrição de identidade
dos perfis está em
[`deployment::os::profile`](../../crates/syrox-engine/src/deployment/os/profile.rs).

Kernel, compiladores e imagens ultrapassam parte desses limites. A implementação
precisa evoluir o modelo de artefatos e recursos antes de adicionar suas receitas.

## 4. Separação dos conceitos públicos

A API deverá distinguir três operações de natureza diferente.

### `Services`

Representa o papel atual de `Os`: pacotes e serviços gerenciados sobre um sistema
existente.

Os perfis de usuário continuam sem autoridade para modificar boot, partições ou
configurações globais.

### `System`

Representa um sistema completo:

- Plataforma.
- Kernel e módulos.
- Userspace.
- Identidade e usuários.
- Configuração de sistema.
- Boot.
- Armazenamento.
- Serviços.
- Política de saúde e atualização.

Um `System` precisa fornecer informações suficientes para construir uma geração
inicializável.

### `HostConfiguration`

Representa recursos que o SRX poderá gerenciar numa distribuição existente.

A configuração seleciona explicitamente quais recursos pertencem ao SRX. Isso
permite adotar sysctls, mounts, serviços ou um kernel sem assumir a propriedade de
toda a instalação.

Os três conceitos compartilharão tipos de domínio, mas terão validações e
operações próprias.

## 5. Responsabilidades entre core, std e catálogo

### Core

O core deverá implementar:

- Planejamento e validação das operações.
- Inspeção de capacidades e dispositivos.
- Verificação e transferência dos artefatos.
- Autoridade de execução.
- Journal, recuperação e retenção.
- Aplicação das operações privilegiadas.
- Observação de boot e saúde.
- Contratos consumidos pelos backends.

### Biblioteca padrão

A std deverá oferecer os tipos e construtores utilizados no `.srx`, incluindo:

- `Services`.
- `System`.
- `HostConfiguration`.
- Kernel e configuração de kernel.
- Boot.
- Grafo de armazenamento.
- Filesystems e mounts.
- Referências a credenciais.
- Política de saúde e persistência.

Avaliar esses valores continuará sendo uma operação sem efeitos sobre a máquina.

### Catálogo

O catálogo deverá conter as receitas e os contratos dos componentes:

- Compiladores e ferramentas.
- Linux e headers.
- libc e bibliotecas.
- systemd, udev e componentes de boot.
- Shell e utilitários.
- Rede e OpenSSH.
- Ferramentas de particionamento, filesystem, criptografia, LVM e RAID.

Versões, fontes, patches, licenças e combinações qualificadas continuarão
pertencendo ao catálogo.

As operações do core não devem conter ramificações por nome de pacote para
executar essas receitas.

## 6. Bootstrap e construção a partir de fontes

Construir a base inteira exige uma cadeia de bootstrap explícita.

O primeiro compilador e suas ferramentas serão entradas autenticadas. A partir
delas, o SRX construirá sua toolchain gerenciada, que será utilizada para produzir
os componentes distribuídos.

O fluxo será:

1. Admitir a semente de ferramentas e registrar sua identidade.
2. Construir os compiladores, binutils, sysroot e ferramentas necessárias.
3. Validar a toolchain gerenciada.
4. Construir o userspace e o kernel com essa toolchain.
5. Verificar que a construção não depende de ferramentas ambientais não declaradas.
6. Produzir os artefatos de sistema e sua proveniência.

A toolchain deverá declarar compilador C/C++, linker, assembler, headers,
bibliotecas e ferramentas auxiliares. O suporte necessário à construção do próprio
SRX também deverá entrar nessa cadeia.

A construção gerenciada não poderá recorrer silenciosamente a `/usr/bin`, headers
ou bibliotecas do host.

Imagens das distribuições existentes poderão ser utilizadas como fixtures de
adoção. Elas serão identificadas, fixadas e registradas como ambientes de teste.

Dependências upstream implementadas em Python ou shell serão empacotadas
normalmente. A manutenção e a orquestração próprias do projeto continuarão em Rust.

## 7. Artefatos grandes e recursos de build

Introduzir uma nova versão dos artefatos para representar saídas maiores sem
exigir blobs gigantes ou carregar imagens inteiras em memória.

O formato utilizará:

- Chunks de 4 MiB.
- Hashes de conteúdo.
- Manifests versionados.
- Transferência e verificação por streaming.
- Referências transitivas para retenção e GC.
- Publicação somente depois da verificação completa.

O GC deverá compreender a relação entre manifests, chunks, gerações instaladas e
operações pendentes.

Criar um perfil de build de sistema com orçamento explícito de:

- Memória.
- CPU.
- Processos e descritores.
- Scratch em disco.
- Quantidade de arquivos.
- Saída.
- Duração.

O administrador do builder definirá os limites admitidos. Um orçamento
incompatível deverá falhar antes de iniciar a construção.

Os perfis existentes manterão seus limites. A mudança não deverá tornar ilimitada
a execução de receitas comuns.

## 8. Configuração do kernel

Configurar o kernel envolve quatro camadas.

| Camada | Exemplos | Momento |
|---|---|---|
| Kconfig | Drivers, filesystems, segurança, recursos de namespaces | Compilação |
| Linha de comando | Console, root, parâmetros de inicialização | Boot |
| Módulos | Inclusão, carregamento e parâmetros | Initramfs ou execução |
| Parâmetros em execução | sysctl e ajustes suportados de dispositivos | Sistema em funcionamento |

Essas camadas deverão aparecer separadas na API e no plano.

### Kconfig

Gerar contratos por versão e arquitetura, oferecendo:

- Autocomplete dos símbolos.
- Tipos booleano, tristate, inteiro, hexadecimal e texto.
- Diagnóstico de nomes desconhecidos.
- Referência ao campo de origem no `.srx`.
- Identidade da configuração efetiva.

A resolução das dependências utilizará o Kconfig upstream. Depois dela, comparar
a configuração final com os valores solicitados e diagnosticar opções que não
puderam ser satisfeitas. Referência:
[documentação Kconfig](https://docs.kernel.org/kbuild/kconfig.html).

### Identidade do kernel

A identidade deverá vincular fonte, patches, configuração, arquitetura,
toolchain, kernel, módulos e headers.

Módulos de configurações incompatíveis não poderão ser misturados. O release
utilizado em runtime deverá distinguir os kernels produzidos pelo SRX.

As versões de referência registradas no estudo são Linux LTS `6.18.57` e systemd
`262.1`. Elas são candidatas do roteiro, sem admissão automática no catálogo:
sua admissão exige fontes verificadas e locks explícitos. Referências:
[Linux](https://www.kernel.org/) e
[systemd](https://github.com/systemd/systemd/releases/tag/v262.1).

### Parâmetros em execução

Cada ajuste deverá declarar sua forma de aplicação e verificação.

Alterações que não admitem restauração confiável serão classificadas no plano.
Configurações que dependem de reboot não serão tratadas como mudanças instantâneas.

Os parâmetros de boot derivados do armazenamento serão gerados a partir do grafo
validado, evitando contradições entre a raiz declarada e a linha de comando.

## 9. Userspace e árvore do sistema

A base inicial deverá fornecer:

- systemd como PID 1.
- udev.
- Shell e utilitários essenciais.
- Rede para a VM.
- OpenSSH.
- SRX e seus componentes de sistema.
- Ferramentas necessárias ao armazenamento.
- Serviços essenciais de inicialização e diagnóstico.

A composição da imagem deverá registrar:

- Caminhos.
- Tipo de entrada.
- Ownership.
- Permissões.
- Links.
- Origem de cada arquivo.
- Conteúdo e identidade dos componentes.

Os prefixos dos pacotes em `/syrox/store/` serão preservados. As exposições em
`/usr`, `/etc` e demais diretórios serão declaradas e verificadas.

Colisões entre componentes deverão ser diagnosticadas antes da geração da imagem.
A composição não poderá incorporar arquivos do host por descoberta implícita.

A imagem deverá funcionar sem o diretório de build, checkout original ou caches
externos.

## 10. Imagens e inicialização

Produzir os artefatos necessários a:

- Rootfs.
- Initramfs.
- UKI.
- Imagem RAW.
- Imagem qcow2.
- ISO UEFI de instalação e resgate.

Utilizar UKIs assinadas para reunir kernel, initramfs, parâmetros e metadados de
boot. A raiz imutável será verificada por dm-verity, com seu hash vinculado à
geração autorizada. Referências:
[UKI](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) e
[dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html).

As partes determinísticas terão verificação de reprodutibilidade. Identidade de
máquina, entropia e material criptográfico serão produzidos por instalação.

Volumes LUKS de instalações diferentes não compartilharão chaves geradas pela
imagem. Imagens de instalação transportarão os artefatos e ferramentas para
provisionar a instância.

## 11. Gerações imutáveis e confirmação de boot

O sistema completo utilizará raiz A/B.

Uma atualização deverá:

1. Verificar os novos artefatos.
2. Preparar o slot inativo.
3. Verificar seu conteúdo.
4. Publicar o kernel e a entrada de boot correspondentes.
5. Registrar a geração como candidata.
6. Programar uma tentativa de boot.
7. Confirmar a geração somente após observar sua saúde.

A confirmação deverá considerar kernel, raiz, volumes persistentes e serviços
essenciais.

A geração saudável anterior continuará disponível durante a tentativa. O
bootloader utilizará contagem de tentativas e fallback. Referência:
[Automatic Boot Assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/).

Um travamento pode exigir watchdog ou novo reset para ocorrer outra tentativa. Os
testes e os relatórios deverão identificar o mecanismo utilizado.

O estado deverá distinguir geração construída, preparada, selecionada,
inicializada e confirmada.

## 12. Dados persistentes e rollback

Kernel, userspace e configuração de sistema pertencem à geração. Dados
persistentes têm um ciclo de vida separado.

Isso inclui:

- Dados de aplicações.
- Diretórios pessoais.
- Credenciais.
- Identidade da instalação.
- Journal.
- Estado necessário à recuperação.

Rollback selecionará uma geração anterior do sistema e sua configuração.

Migrações de dados deverão declarar compatibilidade com as gerações envolvidas.
Uma atualização incompatível exigirá uma estratégia explícita; selecionar uma
raiz anterior não será apresentado como restauração dos dados.

A retenção deverá proteger a geração em execução, a candidata pendente e a geração
saudável necessária ao fallback.

## 13. Modelo de armazenamento

Representar o armazenamento como um grafo de recursos.

A primeira implementação deverá cobrir:

```text
Disco
  └─ Partição GPT
       ├─ ESP
       └─ Dados
            └─ RAID opcional
                 └─ LUKS2 opcional
                      └─ LVM opcional
                           └─ Filesystem ext4
                                └─ Mount
```

O grafo também deverá representar os múltiplos membros das composições RAID;
a árvore acima apresenta a ordem das camadas de uma pilha.

O validador deverá detectar ciclos, referências inválidas, sobreposição,
capacidade insuficiente e composições não suportadas.

A declaração selecionará discos por identidade e propriedades observadas. Nomes
como `/dev/sda` poderão aparecer no diagnóstico, mas não serão a única autoridade
para executar uma escrita.

A resolução deverá exigir um alvo inequívoco e revalidar identidade, geometria e
metadados antes das alterações.

### Particionamento e filesystems

Gerenciar GPT, ESP e ext4 com ferramentas upstream autenticadas.

`systemd-repart` poderá ser utilizado onde sua semântica atende à operação. Ele
adiciona e cresce partições, mas não oferece redução, movimentação ou remoção como
reconciliação geral. Referência:
[documentação do repart](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html).

### LUKS2

Gerenciar criação, abertura, referência e verificação de volumes LUKS2.

Credenciais serão resolvidas por canais privados. O plano deverá mostrar
referências e efeitos sem revelar senhas ou chaves.

A recuperação deverá continuar disponível quando o desbloqueio habitual falhar.
TPM2 será uma expansão posterior. Referência:
[credenciais LUKS2](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html).

### LVM

A primeira implementação utilizará volumes tradicionais com identidade e
capacidade verificadas.

Remover uma declaração não apagará automaticamente um volume.

### RAID

Qualificar:

- RAID1 com duas unidades.
- RAID10 com quatro unidades.

Verificar montagem, perda de membro, reconstrução e retorno ao estado saudável.
As ESPs permanecerão independentes, com conteúdo de boot consistente.

Redundância de armazenamento e recuperação de gerações serão verificadas como
propriedades distintas.

## 14. Autoridade privilegiada

Adicionar um helper privilegiado pequeno em Rust.

O compilador, avaliador e builder continuarão fora desse processo. O helper
receberá operações estruturadas e referências a artefatos já preparados.

Ele deverá:

- Validar o plano e a autoridade do solicitante.
- Reabrir e verificar os recursos reais.
- Restringir as operações ao escopo autorizado.
- Executar ferramentas e operações admitidas.
- Registrar intenção e resultado.
- Verificar o estado observado.
- Preservar operações incertas para recuperação.

O helper não aceitará shell arbitrário fornecido pelo projeto.

Serviços privilegiados serão recursos explícitos do sistema autorizado, com seus
executáveis e configuração vinculados ao plano.

Primitivas Linux compartilhadas deverão ficar numa biblioteca que permita ao
helper operar sem carregar a linguagem e os componentes de build.

## 15. Operações destrutivas e recuperação

Provisionamento será uma operação explícita.

Seu plano deverá mostrar:

- Dispositivos selecionados.
- Identidades observadas.
- Layout anterior.
- Layout pretendido.
- Dados que serão sobrescritos.
- Credenciais necessárias.
- Pré-condições.
- Etapas irreversíveis.
- Procedimento de recuperação.

A autorização será vinculada ao hash desse plano.

Mudanças de dispositivo, metadados ou estado relevante invalidarão o plano.
Operações incompatíveis com discos em uso deverão ser rejeitadas.

O journal deverá permitir observar o que ocorreu após interrupções. A recuperação
não poderá repetir formatação automaticamente para resolver uma dúvida sobre o
resultado anterior.

Quando a evidência for insuficiente, a operação permanecerá incerta e exigirá
reconciliação explícita.

## 16. Adoção de Arch, Debian e Ubuntu

A adoção gerenciará recursos selecionados, preservando a raiz e o gerenciamento de
pacotes da distribuição.

O fluxo será:

1. Inspecionar a instalação.
2. Descobrir capacidades.
3. Identificar recursos existentes e conflitos.
4. Selecionar o que ficará sob gerenciamento do SRX.
5. Registrar ownership.
6. Produzir o plano.
7. Aplicar e verificar os efeitos autorizados.

Os primeiros recursos serão configurações de kernel em execução, módulos,
mounts, serviços e kernels gerenciados.

Kernels novos utilizarão módulos e UKIs em espaços próprios, com entrada UEFI de
teste e preservação do boot anterior. A seleção persistente dependerá da
confirmação de um boot saudável.

Converter uma instalação adotada num sistema SRX completo será uma operação
separada de migração e provisionamento.

Cada distribuição deverá ser qualificada em fixtures fixadas e com suas
capacidades observadas.

## 17. CLI proposta

As interfaces abaixo são propostas para implementação; sua presença nesta tabela
não indica disponibilidade no executável atual.

| Operação | Interface |
|---|---|
| Verificar declarações | `srx project check` |
| Atualizar pins explicitamente | `srx project lock` |
| Inspecionar máquina ou imagem | `srx system inspect` |
| Comparar configuração e estado observado | `srx system plan` |
| Construir imagens | `srx system build` |
| Registrar recursos de uma instalação existente | `srx system adopt` |
| Criar armazenamento e instalar | `srx system provision` |
| Aplicar configuração ou preparar geração | `srx system apply` |
| Consultar estado | `srx system status` |
| Selecionar geração anterior | `srx system rollback` |
| Reconciliar operação interrompida | `srx system recover` |
| Gerenciar o atual conjunto de serviços | `srx services …` |

Construir uma imagem não autorizará sua instalação. Planejar não aplicará
alterações. Preparar uma geração não implicará reboot automático.

## 18. Breaking changes e migração

A expansão permitirá reorganizar a API, mantendo uma migração verificável.

Mudanças principais:

- Renomear o atual `Os` para `Services`.
- Migrar comandos de serviços para `srx services`.
- Introduzir `System` e `HostConfiguration`.
- Versionar manifests, protocolos de build, artefatos e perfis afetados.
- Evoluir os contratos de toolchain.
- Atualizar std, catálogo, exemplos, diagnóstico e autocomplete.
- Atualizar locks explicitamente.

Perfis antigos terão um caminho de migração documentado. A conversão preservará
identidade da instalação e histórico, sem introduzir autoridade privilegiada.

Artefatos publicados não serão silenciosamente reidentificados. Mudanças na
construção produzirão novas identidades, mantendo as evidências anteriores
disponíveis.

## 19. Estratégia de testes

A microVM atual continuará cobrindo os contratos existentes do engine.

A qualificação do sistema completo adicionará QEMU e OVMF, inicializando pelo
firmware e pelo disco. Os testes de boot não utilizarão `-kernel`, pois isso
contorna parte da cadeia que precisa ser verificada.

### Testes de linguagem e planejamento

- Tipos e campos importados.
- Autocomplete de Kconfig.
- Símbolos desconhecidos e valores incompatíveis.
- Grafos de armazenamento inválidos.
- Colisões de arquivos.
- Ownership e permissões.
- Planejamento sem efeitos.

### Artefatos e builders

- Streaming e limites.
- Chunks ausentes ou corrompidos.
- Cancelamento.
- Retenção e GC.
- Recuperação.
- Construção sem dependências ambientais.
- Verificação das partes determinísticas.

### Boot e gerações

- Primeiro boot.
- Atualização A→B.
- Confirmação.
- Candidato defeituoso.
- Retorno à geração anterior.
- UKI adulterada ou não confiável.
- Raiz modificada.
- Interrupções durante publicação e seleção.

### Armazenamento

- Disco simples.
- LUKS2 com LVM.
- RAID1 com LUKS2 e LVM.
- RAID10 com LUKS2 e LVM.
- Credencial incorreta.
- Mudança de identidade do dispositivo.
- Perda e reconstrução de membro.
- Preservação de dados não autorizados.
- Interrupções em etapas destrutivas.

### Adoção

Executar os cenários relevantes em Arch, Debian e Ubuntu, verificando boot
anterior, recursos não gerenciados, configurações em conflito e rollback do kernel.

A falta de KVM ou de outra capacidade necessária será registrada como impedimento
àquela qualificação.

## 20. Etapas de implementação

| Etapa | Resultado verificável |
|---|---|
| 1. Fundações | Artefatos grandes, budgets, manifests, primitivas compartilhadas e inventário somente leitura |
| 2. Bootstrap | Toolchain gerenciada construída e validada |
| 3. Base própria | Userspace e kernel produzidos pelas receitas |
| 4. Boot experimental | Rootfs, initramfs e UKI inicializando em QEMU/OVMF |
| 5. Provisionamento | Helper, journal e pilhas de armazenamento funcionando em discos virtuais |
| 6. Gerações | Atualização, confirmação, fallback, rollback e retenção comprovados |
| 7. Adoção | Arch, Debian e Ubuntu qualificados |
| 8. Publicação | Imagens, fontes, licenças, SBOM, vulnerabilidades e attestations verificáveis |

Cada etapa terá PRs e critérios próprios. Um primeiro boot experimental será
evidência de progresso, sem antecipar a qualificação das etapas seguintes.

O objetivo completo continua aberto. O estado atual é:

| Etapa | Evidência atual | Trabalho obrigatório restante |
|---|---|---|
| Fundações | Migração Services; Store em chunks; resultados v3 e bundles v2 de sistema; produtor de saídas grandes a partir de diretórios e protocolo próprio de transferência worker/coordenador verificado com dois processos; admissão dos oito budgets por configuração local e plano CLI; inventário e comparação de sysctls/binding de discos pela CLI; validadores de orçamento/grafo; System e HostConfiguration na std e planejamento | Perfil de sistema com enforcement e integração do protocolo ao executor; receipts/autorizações de catálogo; integração dos planos com aplicação e builds de sistema |
| Bootstrap | Toolchain gerenciada atual disponível para receitas comuns | Semente autenticada e cadeia completa de compiladores, sysroot e Rust qualificada |
| Base própria | Sem userspace/kernel próprios qualificados | Receitas e builds de todos os componentes mínimos |
| Boot experimental | Composição, initramfs, dm-verity, GPT RAW e qcow2 por streaming na Store; sem sistema próprio inicializável | Pipeline System/CLI, rootfs, initramfs funcional, UKI assinada, ISO e boot por OVMF/disco |
| Provisionamento | Validação de layouts; helper de scratch privado e journal/recuperação no mesmo boot verificados em VM | Operações privilegiadas de provisionamento; ferramentas das pilhas, credenciais e testes destrutivos em discos virtuais |
| Gerações | Gerações atuais de serviços preservadas | Raiz A/B, saúde, confirmação, fallback, rollback e retenção de sistemas completos |
| Adoção | Inventário e comparação somente leitura de sysctls declarados pela CLI de planos | Ownership, contratos de aplicação/restauração, módulos, mounts, serviços e fixtures de Arch, Debian e Ubuntu |
| Publicação | Identidades CAS existentes preservadas | Imagens qualificadas, fontes/licenças/SBOM, assinaturas, vulnerabilidades e attestations |

O ambiente observado continua sem `/dev/kvm` e sem QEMU no `PATH`. A leitura de
sysfs/proc e as fixtures de validação não substituem a qualificação por firmware,
disco e boot. As etapas independentes dessas capacidades continuam autorizadas.

## 21. Publicação e manutenção

As imagens deverão incluir evidências de:

- Revisão do core e catálogo.
- Fontes, patches e configurações.
- Toolchain e semente.
- Dependências e licenças.
- SBOM.
- Verificação de vulnerabilidades.
- Testes e ambientes.
- Checksums.
- Proveniência.
- Verificação das assinaturas.

As políticas atuais de locks explícitos, identidade de artefatos e publicação
qualificada serão estendidas aos componentes do sistema.

Mudanças no kernel, configuração, toolchain, armazenamento ou boot produzirão
novas identidades e exigirão a qualificação correspondente.

## 22. Limites do primeiro ciclo

O primeiro ciclo contempla x86_64, UEFI, systemd, console, rede, SSH, gerações
imutáveis, Secure Boot, ext4, LUKS2, LVM, RAID1 e RAID10.

Ficam para expansões posteriores:

- Desktop gráfico e integração de GPU/áudio.
- ARM64 e outras arquiteturas.
- BIOS legado.
- TPM2.
- Btrfs e ZFS.
- RAID0, RAID5 e RAID6.
- Redução e movimentação de volumes.
- Atualização de firmware da máquina.
- Migração automática da raiz de uma distribuição.
- Qualificação de hardware físico.

O ambiente local observado em 21 de outubro de 2026 não tem `/dev/kvm`. A
implementação precisará de um builder e ambiente de teste com recursos adequados
antes de afirmar a qualificação do sistema completo.
