#!/bin/bash
echo "Iniciando o OWASP ZAP em modo daemon..."
/opt/ZAP/zap.sh -daemon -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true &

echo "ZAP iniciando na porta 8080"
echo "Aguarda alguns segundos, antes de execucar o scanner..."
