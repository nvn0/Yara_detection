/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

/*
rule domain {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $domain_regex = /([\w\.-]+)/ wide ascii
    condition:
        $domain_regex
}
*/

rule Detect_DomainsV2
{
    meta:
        author = "ChatGPT"
        description = "Regra para detectar padrões de domínios em arquivos"
        date = "2024-07-22"
    
    strings:
        // Regex aprimorada para capturar melhor a estrutura de um domínio
        $domain_regex = /([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/ wide ascii
    
    condition:
        $domain_regex
}