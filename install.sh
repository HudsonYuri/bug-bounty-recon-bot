#!/bin/bash
# install.sh - Script de instalação do Bug Bounty Bot

echo "🔧 Instalando Bug Bounty Bot..."

# Criar diretórios
mkdir -p workspace
mkdir -p tools/wordlists
mkdir -p reports

# Instalar dependências Python
pip3 install -r /home/kali/Desktop/requirements.txt

# Baixar wordlists
echo "📥 Baixando wordlists..."
cd tools/wordlists

# Wordlist de subdomínios
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains.txt

# Wordlist de diretórios
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O directories.txt

cd ../..

# Verificar ferramentas externas
echo "🔍 Verificando ferramentas externas..."

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✅ $1 instalado"
    else
        echo "❌ $1 não encontrado (opcional)"
    fi
}

check_tool "nmap"
check_tool "nuclei"
check_tool "httpx"
check_tool "subfinder"
check_tool "amass"

echo ""
echo "✅ Instalação concluída!"
echo ""
echo "📝 Para usar: python3 bugbounty_bot.py -d exemplo.com"
