# ORCSec: Detecção de UE Malicioso em Redes O-RAN com xApps e Classificação Cascateada por ML

Este artefato apresenta a implementação do framework **ORCSec**, uma abordagem para detecção de comportamento malicioso de Equipamentos de Usuário (UEs) em redes O-RAN. O sistema integra coleta de métricas E2SM-KPM Style 5, engenharia de características temporais e inferência cascateada multi-estágio dentro de um Near-RT RIC, utilizando xApps Python para monitoramento e classificação em tempo real.

**Título do Trabalho:** ORCSec — Framework de Orquestração de Experimentos e Detecção de UE Malicioso Baseada em ML sobre Métricas O-RAN KPM Style 5

**Contexto Acadêmico:** Dissertação de Mestrado — Análise de Telemetria RAN Online para Detecção de Comportamento Malicioso de UEs com Classificação Multi-estágio e Extração de Features Temporais em Testbed O-RAN Near-RT RIC

**Resumo:** Este trabalho propõe o ORCSec, um framework ponta a ponta para geração de experimentos multi-UE 4G/5G (tráfego benigno e de ataque), coleta de métricas padronizadas O-RAN via KPM Style 5, engenharia de características temporais e classificação cascateada (Estágio 1 binário + Estágio 2 subtipo) de UEs maliciosos dentro de um Near-RT RIC. O detector opera sobre buffers de métricas em memória, sem escrita de CSVs intermediários, garantindo inferência online de baixa latência. O sistema suporta perfis de ataque como UDP flood, TCP flood, fragmentação e variantes pulsantes, além de subtipagem de tráfego benigno (eMBB, MTC, URLLC, VoIP).

---

## Estrutura do readme.md

Este documento está organizado nas seguintes seções:

- [Título e Resumo](#orcsec-detecção-de-ue-malicioso-em-redes-o-ran-com-xapps-e-classificação-cascateada-por-ml): Descrição geral do projeto e contexto acadêmico
- [Estrutura do readme.md](#estrutura-do-readmemd): Esta seção (organização do documento)
- [Selos Considerados](#selos-considerados): Selos de qualidade aplicáveis ao artefato
- [Informações básicas](#informações-básicas): Requisitos de hardware e software
- [Dependências](#dependências): Bibliotecas e versões necessárias
- [Preocupações com segurança](#preocupações-com-segurança): Considerações de segurança
- [Instalação](#instalação): Processo de instalação do ambiente
- [Teste mínimo](#teste-mínimo): Verificação básica de funcionamento
- [Experimentos](#experimentos): Reprodução dos resultados do artigo
- [LICENSE](#license): Licença do projeto

---

## Selos Considerados

Os selos considerados são: **Disponíveis (SeloD)**, **Funcionais (SeloF)**, **Sustentáveis (SeloS)** e **Experimentos Reprodutíveis (SeloR)**.

---

## Informações básicas

### ⚠️ Sistemas Operacionais Suportados

#### Linux (Recomendado)
O projeto foi desenvolvido e testado em ambiente Linux (Ubuntu 20.04+). Siga as instruções normalmente.

#### Windows
Para executar no Windows, é **NECESSÁRIO** usar o WSL2 (Windows Subsystem for Linux):

```bash
wsl --install -d Ubuntu-24.04
```

Dentro do WSL, instale os pacotes necessários:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git build-essential docker.io docker-compose
```

### Ambiente de Execução

#### Hardware Recomendado
| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Disco | 20 GB livres | 50 GB livres |
| GPU | — (não necessária) | Opcional (aceleração de modelos PyTorch) |

#### Software Necessário
- **Sistema Operacional:** Linux Ubuntu 20.04+ ou Windows com WSL2
- **Python:** 3.8 ou superior
- **Docker:** 20.10+ com Docker Compose
- **Git:** Para clonar o repositório e submódulos
- **GNU Radio:** Para simulação de canal RF (cenários de fading multi-UE)
- **tmux:** Para gerenciamento de sessões de processos paralelos

### Estrutura do Repositório

```
ORCSec/
├── detector_xapp.py               # xApp detector de UE malicioso (inferência cascateada)
├── kpm5_xapp.py                   # xApp coletor de métricas KPM Style 5
├── generate_experiments.py        # Gerador de experimentos benignos
├── generate_malicious_experiments.py  # Gerador de experimentos com tráfego malicioso
├── mmap_generator.py              # Gerador estocástico M-map para atribuição de perfis
├── metrics_server.py              # Servidor de métricas auxiliar
├── gnb_zmq.yaml                   # Configuração do gNB srsRAN com ZMQ
├── multi_ue_scenario.grc          # Cenário GNU Radio para simulação de canal RF
├── dataset/
│   └── ue_data.csv                # Dados de configuração por UE
├── openran/
│   ├── my-srsproject-demo/        # Configurações e scripts do srsRAN
│   │   ├── config/                # Configurações gNB e UE (ZMQ)
│   │   └── multi-ue-setup/        # Cenários GNU Radio multi-UE
│   ├── oran-sc-ric/               # Stack Near-RT RIC (O-RAN SC)
│   │   ├── docker-compose.yml     # Orquestração dos componentes RIC
│   │   ├── ric/configs/           # Configurações dos serviços RIC
│   │   └── xApps/python/          # xApps Python e bibliotecas
│   │       ├── lib/               # Módulos E2SM-KPM, ML, xAppBase
│   │       └── *.joblib           # Artefatos dos modelos ML treinados
│   ├── srsRAN_4G/                 # Fonte srsRAN 4G (submódulo)
│   └── srsRAN_Project/            # Fonte srsRAN Project 5G (submódulo)
└── README.md                      # Este arquivo
```

### Descrição dos Componentes Principais

| Componente | Arquivo(s) | Descrição |
|------------|-----------|-----------|
| xApp Detector | `detector_xapp.py` | Subscreve KPM Style 5, engenharia de features, predição cascateada (Estágio 1 binário → Estágio 2 subtipo) |
| xApp Coletor KPM | `kpm5_xapp.py` | Subscreve KPM Style 5, grava CSV largo (uma linha por UE por indicação) |
| Base xApp | `openran/oran-sc-ric/xApps/python/lib/xAppBase.py` | Abstração de RMR, callbacks HTTP, threading e despacho de subscrições |
| Módulo E2SM-KPM | `openran/oran-sc-ric/xApps/python/lib/e2sm_kpm_module.py` | Empacotamento/desempacotamento de indicações e payloads de subscrição KPM |
| Modelos ML | `openran/oran-sc-ric/xApps/python/lib/ml_models.py` | Arquiteturas CNN-GRU e CNN-LSTM usadas em treinamento/inferência |
| Gerador Benigno | `generate_experiments.py` | Cria pastas de experimentos com atribuição estocástica M-map de perfis benignos |
| Gerador Malicioso | `generate_malicious_experiments.py` | Mesmo fluxo, porém injeta 2 UEs maliciosos por execução |
| Orquestrador | `run_enhanced.sh` | Inicia/para toda a pilha (RIC, core, gNB, UEs, GNU Radio, tráfego), com retentativas e validações |
| Cenário GNU Radio | `multi_ue_scenario.grc` / scripts gerados | Fornece dinâmica de canal RF e degradação de sinal |

---

## Dependências

### Bibliotecas Python Principais

```
torch>=1.10.0
numpy>=1.21.0
pandas>=1.3.0
scikit-learn>=0.24.0
joblib>=1.1.0
```

### Dependências de Sistema

| Dependência | Versão Mínima | Finalidade |
|------------|--------------|-----------|
| Docker | 20.10+ | Execução do stack RIC e Open5GS |
| Docker Compose | 1.29+ | Orquestração dos contêineres |
| GNU Radio | 3.8+ | Simulação de canal RF multi-UE |
| tmux | 3.0+ | Gerenciamento de sessões paralelas |
| iperf3 | 3.9+ | Geração de tráfego por perfil |
| Python | 3.8+ | xApps e scripts de orquestração |

### Instalação das Dependências Python

```bash
pip install torch numpy pandas scikit-learn joblib
```

---

## Preocupações com segurança

> ⚠️ Este artefato **simula tráfego de ataque em ambiente controlado**. Utilize exclusivamente em testbeds isolados de rede.

- **Namespaces de rede isolados:** Os UEs (`ue1`, `ue2`, `ue3`) operam em network namespaces Linux separados, sem impacto em interfaces físicas do host.
- **Portas reservadas:** O orquestrador ocupa as portas `2000–2301` e `55555`. Não execute serviços de produção nestas portas durante os experimentos.
- **Rotas adicionadas:** A rota `10.45.0.0/16 via 10.53.1.2` é inserida temporariamente e removida no teardown automático.
- **Processos forçados:** O script mata processos nas portas listadas acima ao iniciar. Evite serviços não relacionados nessas portas.
- **Dados locais apenas:** O framework não realiza conexões externas à internet; processa apenas dados locais e tráfego sintético gerado internamente.
- **Artefatos ML locais:** Os modelos `.joblib` são carregados de arquivos locais; nenhum código externo é executado.
- **Limpeza automática:** Namespaces de rede, sessões tmux e contêineres Docker são removidos automaticamente ao final de cada execução.

---

## Instalação

> **Nota para usuários Windows:** Execute todos os comandos abaixo dentro do WSL2/Ubuntu.

### 1. Clonar o Repositório com Submódulos

```bash
git clone --recurse-submodules https://github.com/<seu-usuario>/ORCSec.git
cd ORCSec
```

Se já clonou sem submódulos:

```bash
git submodule update --init --recursive
```

### 2. Criar Ambiente Virtual Python

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS/WSL
```

### 3. Instalar Dependências Python

```bash
pip install --upgrade pip
pip install torch numpy pandas scikit-learn joblib
```

### 4. Instalar Docker e Docker Compose

```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo usermod -aG docker $USER
newgrp docker
```

### 5. Subir o Stack Near-RT RIC

```bash
cd openran/oran-sc-ric
docker compose up -d
cd ../..
```

Aguarde até que todos os contêineres estejam saudáveis:

```bash
docker compose -f openran/oran-sc-ric/docker-compose.yml ps
```

### 6. Verificar Artefatos dos Modelos ML

Confirme que os arquivos de modelos estão presentes:

```bash
ls openran/oran-sc-ric/xApps/python/*.joblib
# Esperado: s1_model.joblib  s2_benign_model.joblib  s2_malicious_model.joblib
```

---

## Teste mínimo

Execute o seguinte comando para verificar se a instalação foi bem-sucedida:

```bash
python3 -c "
import torch, numpy, pandas, sklearn, joblib
print('[OK] PyTorch:', torch.__version__)
print('[OK] NumPy:', numpy.__version__)
print('[OK] Pandas:', pandas.__version__)
print('[OK] scikit-learn:', sklearn.__version__)

import os
models = ['openran/oran-sc-ric/xApps/python/s1_model.joblib',
          'openran/oran-sc-ric/xApps/python/s2_benign_model.joblib',
          'openran/oran-sc-ric/xApps/python/s2_malicious_model.joblib']
for m in models:
    status = '[OK]' if os.path.exists(m) else '[AUSENTE]'
    print(f'{status} Modelo: {m}')

ric_up = os.system('docker compose -f openran/oran-sc-ric/docker-compose.yml ps --quiet 2>/dev/null | wc -l') == 0
print('[OK] Verificação de dependências concluída.')
"
```

**Saída esperada:**
```
[OK] PyTorch: 2.x.x
[OK] NumPy: 1.x.x
[OK] Pandas: 2.x.x
[OK] scikit-learn: 1.x.x
[OK] Modelo: openran/oran-sc-ric/xApps/python/s1_model.joblib
[OK] Modelo: openran/oran-sc-ric/xApps/python/s2_benign_model.joblib
[OK] Modelo: openran/oran-sc-ric/xApps/python/s2_malicious_model.joblib
[OK] Verificação de dependências concluída.
```

**Tempo esperado:** < 10 segundos

---

## Experimentos

### Experimento 1: Coleta de Métricas KPM Style 5 (xApp Coletor)

Inicia o xApp de coleta de métricas KPM E2SM Style 5:

```bash
cd openran/oran-sc-ric
docker compose exec python_xapp_runner bash -c \
  "./kpm5_xapp.py --metrics_dir metrics --ue_ids 0,1,2"
```

**Saída esperada:** CSV em `metrics/kpm_style5_metrics.csv` com colunas:
```
Timestamp, E2AgentID, SubscriptionID, UE_ID, Granularity,
RRU.PrbUsedDl, RRU.PrbUsedUl, DRB.UEThpDl, DRB.UEThpUl,
CQI, RSRP, RSRQ, DRB.RlcSduDelayDl, ...
```

---

### Experimento 2: Detecção de UE Malicioso (xApp Detector — Reivindicação Principal)

**Reivindicação:** O detector cascateado classifica corretamente UEs maliciosos com inferência em memória, sem necessidade de CSVs intermediários.

#### Execução:

```bash
cd openran/oran-sc-ric
docker compose exec python_xapp_runner bash -c \
  "./detector_xapp.py \
    --s1_model_path s1_model.joblib \
    --s2_ben_path s2_benign_model.joblib \
    --s2_mal_path s2_malicious_model.joblib \
    --buffer_size 60 --ue_ids 0,1,2"
```

#### Configuração:
- `--buffer_size 60`: janela de 60 amostras por UE antes de inferência
- `--ue_ids 0,1,2`: IDs dos UEs monitorados
- Modelos carregados de arquivos `.joblib` locais

#### Recursos esperados:
- **RAM:** 4 GB
- **Disco:** < 500 MB
- **Tempo:** Contínuo (online, até interrupção manual)
- **GPU:** Opcional

#### Resultado esperado (saída do detector):
```
[INFO] Stage 1 - Binary Classification:
  UE 0 → Benign   (confiança: 0.91)
  UE 1 → Malicious (confiança: 0.87)
  UE 2 → Benign   (confiança: 0.95)

[INFO] Stage 2 - Subtype Classification:
  UE 0 → embb
  UE 1 → udp_flood
  UE 2 → urllc

[INFO] Buffer processado: 60 amostras / UE. Próximo ciclo em andamento...
```

#### Análise dos Resultados:
- **Classificação binária (Estágio 1):** separa UEs benignos de maliciosos por votação majoritária sobre o buffer
- **Subtipagem (Estágio 2):** dois modelos especialistas — subtipo benigno (embb, mtc, urllc, voip) e subtipo malicioso (udp_flood, tcp_flood, fragmentação, etc.)
- **Features derivadas:** razões de utilização PRB, normalização de throughput, métricas de jitter RLC, índice de sinal composto (CQI+RSRP+RSRQ)/3, flags de inatividade, médias/desvios em janelas deslizantes (tamanho=5)

---

### Experimento 3: Geração de Dataset de Experimentos

#### 3.1 Experimentos Benignos

```bash
python3 generate_experiments.py
# Gera 50 execuções em dataset/generated_experiments/trX/expY/
```

#### 3.2 Experimentos com Tráfego Malicioso

```bash
python3 generate_malicious_experiments.py
# Gera 100 execuções com 2 UEs maliciosos por execução
```

Cada pasta de experimento gerada contém:
```
conditions.csv       # Mapeamento UE ↔ perfil iperf + parâmetros M-map e canal
run_scenario.sh      # Inicia cenário GNU Radio e salva PID em /tmp/python_scenario.pid
metrics/             # Métricas de saída (se xApp coletor utilizado)
ue_logs/             # Logs por UE, CSV de métricas, pcap, rastreamento
gnb_logs/            # Logs do gNB, rastreamentos pcap
```

---

### Experimento 4: Pipeline Completo Automatizado

Para reproduzir uma execução completa orquestrada (RIC + core + gNB + UEs + GNU Radio + tráfego + coleta):

```bash
bash run_enhanced.sh 0 1   # conjunto de treino 0, experimento 1
```

**Fases executadas automaticamente:**
1. Inicia Near-RT RIC (Docker Compose) → aguarda saúde de `ric_submgr`
2. Inicia core Open5GS → aguarda healthcheck do contêiner
3. Inicia gNB srsRAN com logging de métricas e pcap
4. Cria namespaces de rede e inicia 3 instâncias srsUE (configs de `ue_data.csv`)
5. Lança cenário GNU Radio de fading/canal via `run_scenario.sh` do experimento
6. Inicia tráfego iperf por UE conforme perfis em `conditions.csv`
7. (Opcional) Executa xApps KPM coletor/detector via contêiner `python_xapp_runner`
8. Valida duração das métricas, limpa (sessões tmux, namespaces, Docker, portas, temporários)

**Recursos esperados:**
- **RAM:** 16 GB
- **Disco:** 5–10 GB por execução completa
- **Tempo:** ~8–15 minutos por experimento (configurável via `DURATION_SEC`)
- **Portas utilizadas:** 2000–2301, 55555

---

## LICENSE

Este projeto está licenciado sob os termos das licenças upstream dos componentes utilizados:

- **O-RAN SC RIC:** Apache License 2.0
- **srsRAN 4G / srsRAN Project:** GNU Affero General Public License v3.0
- **Open5GS:** GNU Affero General Public License v3.0
- **Scripts e xApps locais (`detector_xapp.py`, `kpm5_xapp.py`, `generate_*.py`, etc.):** MIT License

```
MIT License

Copyright (c) 2025 ORCSec Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

Consulte os arquivos `openran/srsRAN_4G/LICENSE`, `openran/srsRAN_Project/LICENSE` e `openran/oran-sc-ric/LICENSE` para os termos completos dos componentes de código aberto incluídos como submódulos.
