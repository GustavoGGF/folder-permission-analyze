# Listar grupos e permissões

Aplicativo para Windows que analisa as permissões de uma pasta local ou de um
compartilhamento de rede SMB e gera uma planilha Excel com os grupos, usuários
e permissões encontrados.

O programa lê a ACL/DACL da pasta, identifica os grupos que possuem regras de
acesso e consulta os membros desses grupos no Windows local ou no Active
Directory. O relatório é salvo no formato `.xlsx`.

## Requisitos

- Windows 10 ou superior;
- Python 3.10 ou superior, caso o programa seja executado pelo código-fonte;
- acesso à pasta que será analisada;
- conexão com o domínio/Active Directory, quando os grupos forem do domínio.

O projeto usa APIs de segurança do Windows (`pywin32`) e, portanto, não é
compatível com Linux ou macOS.

## Usar o executável

Se você recebeu `ListarGruposPermissao.exe`:

1. Execute o arquivo no Windows.
2. Clique em **Procurar...** e escolha a pasta local ou de rede.
3. Clique em **Gerar planilha**.
4. Abra o arquivo `grupos_permissoes.xlsx` criado dentro da pasta analisada.

Para uma pasta de rede, informe ou selecione um caminho semelhante a:

```text
\\servidor\compartilhamento\pasta
```

O relatório contém:

- a aba **Grupos**, com o nome de cada grupo e sua permissão consolidada;
- uma aba para cada grupo, com os usuários/membros encontrados;
- mensagens de erro de consulta de membros, quando o Windows não conseguir
  consultar algum grupo.

O executável pode precisar ser iniciado por uma conta que tenha permissão para
ler a pasta e consultar os grupos. Não é necessário executar como administrador
se a conta já tiver os acessos necessários.

## Executar pelo código-fonte

Abra o **Prompt de Comando** ou o **PowerShell** na pasta do projeto e execute:

```bat
python -m pip install -r requirements.txt
python listar_grupos_permissao.py
```

Sem argumentos, o programa abre a interface gráfica para selecionar a pasta.

Também é possível informar a pasta diretamente:

```bat
python listar_grupos_permissao.py "C:\Dados\Compartilhamento"
```

Nesse caso, a planilha será criada como:

```text
C:\Dados\Compartilhamento\grupos_permissoes.xlsx
```

Para escolher outro arquivo de saída:

```bat
python listar_grupos_permissao.py "\\servidor\compartilhamento" -o "C:\Relatorios\permissoes.xlsx"
```

Para abrir a interface gráfica explicitamente:

```bat
python listar_grupos_permissao.py --gui
```

## Gerar um novo `.exe`

O executável deve ser compilado no Windows, pois a aplicação depende das APIs
de segurança do Windows. Na pasta do projeto, execute:

```bat
gerar_exe.bat
```

O script instala as dependências e cria o arquivo em:

```text
dist\ListarGruposPermissao.exe
```

## Testes

Os testes podem ser executados no Windows com:

```bat
python -m unittest discover -s tests -v
```

## Publicar no GitHub

Para publicar este projeto em um repositório público:

1. Crie um repositório vazio no GitHub, sem adicionar outro README.
2. Na pasta do projeto, configure o usuário do Git, se necessário.
3. Execute os comandos abaixo, substituindo a URL pelo seu repositório:

```bat
git init
git add .
git commit -m "Publica aplicativo de análise de permissões"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
git push -u origin main
```

Antes de tornar o repositório público, verifique se ele não contém senhas,
tokens, dados reais de usuários, caminhos internos ou planilhas geradas com
informações confidenciais. Arquivos `.xlsx`, pastas de build e ambientes
virtuais já estão configurados no `.gitignore` para não serem enviados por
engano.

## Limitações

- funciona somente no Windows;
- a leitura depende das permissões da conta que executa o programa;
- a consulta dos membros depende da disponibilidade do computador, servidor
  de arquivos ou Active Directory;
- o relatório representa as regras encontradas na ACL da pasta analisada e não
  substitui uma auditoria completa de permissões efetivas herdadas.
