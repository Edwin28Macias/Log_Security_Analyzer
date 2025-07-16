# Log_Security_Analyzer
**Descrição:** Um script Python para parsear e analisar logs de firewall, com foco na sumarização de tráfego denegado e detecção de padrões de segurança.

## Funcionalidades Atuais

Este script Python já oferece as seguintes funcionalidades:

* **Leitura e Parseamento de Logs:** Utiliza a função `load_logs_from_file()` para ler arquivos de log de firewall e processar cada linha, transformando-as em dados estruturados.
* **Análise de Tráfego Denegado:** Através da função `generate_denied_traffic_summary()`, o script identifica e sumariza as entradas de log onde a ação foi "DENY", listando o total e as IPs de origem únicas envolvidas.
* **Exibição de Entradas Iniciais:** A função `display_first_entries()` permite uma rápida visualização das primeiras entradas de log parseadas para verificação.
* **Tratamento de Erros:** Inclui mecanismos para lidar com arquivos não encontrados e linhas de log que não correspondem ao padrão esperado.

---

## Próximos Passos (Desenvolvimento Contínuo)

Estamos constantemente aprimorando este analisador. As próximas funcionalidades planejadas incluem:

* **Filtragem Avançada de Logs:** Implementar a capacidade de filtrar logs por critérios específicos (como endereço IP, protocolo, ação "ALLOW", ou período de tempo).
* **Identificação de Padrões de Ataque:** Desenvolver algoritmos para detectar padrões anormais, como varreduras de porta ou tentativas de força bruta, a partir dos dados do log.
* **Geração de Relatórios:** Adicionar opções para exportar os resultados da análise para formatos como CSV ou JSON, facilitando o compartilhamento e a integração com outras ferramentas.
* **Comentários Detalhados no Código:** Adicionar comentários explicativos nos fragmentos de código para facilitar a compreensão e a manutenção futura.
