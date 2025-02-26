#!/bin/bash

# Путь к файлу
file="/etc/V2bX/custom_outbound.json"

# Проверяем, существует ли файл
if [ ! -f "$file" ]; then
  echo "Файл не найден: $file"
  exit 1
fi

# Убираем блок с "tag": "block"
jq 'del(.[] | select(.tag == "block"))' "$file" > "$file.tmp" && mv "$file.tmp" "$file"

# Перезапускаем сервис
v2bx restart

echo "Файл обновлен и сервис перезапущен."
