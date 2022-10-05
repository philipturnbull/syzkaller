grep 'transitively unsupported' | grep -Eo '\[[^]]+\]' | tr -d '[]' | tr ' ' '\n'
