"""Lista grupos que aparecem na ACL de uma pasta Windows/SMB e exporta para Excel.

Este módulo lê a lista de controle de acesso discricionária (DACL) de um diretório
local ou compartilhamento de rede SMB no Windows, identifica quais grupos possuem
permissões atribuídas, consulta os membros de cada grupo (Active Directory ou local)
e gera um relatório formatado em planilha Excel (.xlsx).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, TypedDict

# =====================================================================
# Constantes de Direitos de Acesso do Windows (Access Mask Bits)
# Referência: https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
# =====================================================================

FILE_READ_DATA = 1            # 0x00000001: Direito de ler dados do arquivo / listar diretório
FILE_WRITE_DATA = 2           # 0x00000002: Direito de gravar dados no arquivo / criar arquivo
FILE_APPEND_DATA = 4          # 0x00000004: Direito de anexar dados / criar subdiretório
FILE_READ_EA = 8              # 0x00000008: Direito de ler atributos estendidos (EA)
FILE_WRITE_EA = 16            # 0x00000010: Direito de gravar atributos estendidos (EA)
FILE_EXECUTE = 32             # 0x00000020: Direito de executar arquivo / percorrer pasta
FILE_DELETE_CHILD = 64        # 0x00000040: Direito de excluir arquivos e subpastas
FILE_READ_ATTRIBUTES = 128    # 0x00000080: Direito de ler atributos do sistema de arquivos
FILE_WRITE_ATTRIBUTES = 256   # 0x00000100: Direito de alterar atributos do sistema de arquivos
DELETE = 65536                # 0x00010000: Direito padrão de excluir o próprio objeto
READ_CONTROL = 131072         # 0x00020000: Direito de ler a DACL e proprietário
WRITE_DAC = 262144            # 0x00040000: Direito de modificar a DACL
WRITE_OWNER = 524288          # 0x00080000: Direito de alterar o proprietário do objeto
SYNCHRONIZE = 1048576         # 0x00100000: Direito de sincronização no Windows

# Flag de controle de ACE (Access Control Entry)
INHERITED_ACE = 16            # 0x10: Indica se a ACE foi herdada do diretório pai

# Máscaras compostas para verificação simplificada de Leitura e Escrita
READ_BITS = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES
WRITE_BITS = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES

# =====================================================================
# Configurações de Grupos e Níveis de Permissão
# =====================================================================

# Tipos de SID reconhecidos como grupos pelo Windows Security
GROUP_ACCOUNT_TYPES = {"SidTypeGroup", "SidTypeDomainGroup", "SidTypeAlias"}

# Grupos administrativos excluídos do relatório final por convenção
IGNORED_GROUP_NAMES = {"admins. do domínio"}

# Hierarquia numérica de privilégios para desempate na consolidação de regras
PERMISSION_LEVELS = {
    "WRITE": 1,
    "READ": 2,
    "READ_AND_EXECUTE": 3,
    "MODIFY": 4,
    "FULL_CONTROL": 5,
}

# Mapeamento numérico padrão para tipos de SID (caso pywin32 retorne inteiros)
SID_TYPE_NAMES = {
    2: "SidTypeDomainGroup",
    4: "SidTypeAlias",
    5: "SidTypeWellKnownGroup",
}

DEFAULT_OUTPUT_NAME = "grupos_permissoes.xlsx"


class GroupEntry(TypedDict, total=False):
    """Representa uma entrada de permissão para um grupo."""

    grupo: str
    sid: str
    tipo: str
    permissoes: list[str]
    herdada: bool
    membros: list[str]
    membros_erro: str


# =====================================================================
# Verificação e Decodificação de Permissões
# =====================================================================

def is_group_account(sid_type: Any) -> bool:
    """Verifica se o tipo de SID informado corresponde a uma conta de grupo."""
    if isinstance(sid_type, int):
        sid_type = SID_TYPE_NAMES.get(sid_type, "")
    return str(sid_type) in GROUP_ACCOUNT_TYPES


def is_inherited_ace(ace_flags: int) -> bool:
    """Retorna True se a ACE tiver a flag de herança (INHERITED_ACE) ativada."""
    return bool(ace_flags & INHERITED_ACE)


def permission_names(mask: int) -> list[str]:
    """Decodifica a máscara binária de acesso do Windows em nomes de permissão legíveis."""
    names: list[str] = []

    # Se todos os bits de leitura estiverem presentes, simplifica como 'READ'
    if mask & READ_BITS == READ_BITS:
        names.append("READ")
    else:
        names.extend(
            name
            for bit, name in (
                (FILE_READ_DATA, "READ_DATA"),
                (FILE_READ_EA, "READ_EA"),
                (FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"),
            )
            if mask & bit
        )

    # Se todos os bits de escrita estiverem presentes, simplifica como 'WRITE'
    if mask & WRITE_BITS == WRITE_BITS:
        names.append("WRITE")
    else:
        names.extend(
            name
            for bit, name in (
                (FILE_WRITE_DATA, "WRITE_DATA"),
                (FILE_APPEND_DATA, "APPEND_DATA"),
                (FILE_WRITE_EA, "WRITE_EA"),
                (FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
            )
            if mask & bit
        )

    # Direitos específicos e padrão adicionais
    other_rights = (
        (FILE_EXECUTE, "EXECUTE"),
        (FILE_DELETE_CHILD, "DELETE_CHILD"),
        (DELETE, "DELETE"),
        (READ_CONTROL, "READ_CONTROL"),
        (WRITE_DAC, "WRITE_DAC"),
        (WRITE_OWNER, "WRITE_OWNER"),
        (SYNCHRONIZE, "SYNCHRONIZE"),
    )
    names.extend(name for bit, name in other_rights if mask & bit)
    return names


def _group_name(group: str) -> str:
    """Extrai apenas o nome do grupo em minúsculas, descartando o domínio/máquina."""
    return group.casefold().split("\\")[-1]


def _normalized_permissions(permissions: list[str]) -> list[str]:
    """Normaliza conjuntos de permissões individuais para perfis de alto nível (MODIFY, FULL_CONTROL)."""
    values = set(permissions)
    if {"READ", "WRITE", "DELETE", "WRITE_DAC", "WRITE_OWNER"}.issubset(values):
        return ["FULL_CONTROL"]
    if "READ" in values and "WRITE" in values:
        return ["MODIFY"]
    return permissions


def _permission_level(permissions: list[str]) -> int:
    """Retorna o nível hierárquico máximo entre as permissões informadas."""
    return max((PERMISSION_LEVELS.get(permission, 0) for permission in permissions), default=0)


def collapse_group_permissions(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Consolida permissões de grupos repetidos, mantendo a de maior privilégio.

    Entradas referentes a grupos na lista de ignorados (ex.: administradores do domínio)
    são descartadas da listagem final.
    """
    collapsed: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    for entry in entries:
        if _group_name(entry.get("grupo", "")) in IGNORED_GROUP_NAMES:
            continue
        key = (entry.get("grupo"), entry.get("sid"), entry.get("tipo"))
        permissions = _normalized_permissions(entry.get("permissoes", []))
        current = collapsed.get(key)
        if current is None or _permission_level(permissions) > _permission_level(current["permissoes"]):
            current = dict(entry)
            current["permissoes"] = permissions
            collapsed[key] = current
    return list(collapsed.values())


def permission_label(permissions: list[str]) -> str:
    """Converte permissões técnicas para uma descrição amigável em português."""
    technical = set(permissions)
    if technical.issubset({"READ", "EXECUTE", "READ_CONTROL", "SYNCHRONIZE"}):
        return "Leitura"
    if technical == {"MODIFY"}:
        return "Modificar"
    if technical == {"FULL_CONTROL"}:
        return "Controle total"
    return "Personalizada"


# =====================================================================
# Consulta de Membros e Segurança do Windows (pywin32)
# =====================================================================

def _find_domain_controller(domain: str) -> str | None:
    """Tenta localizar o nome de um Controlador de Domínio (DC) para o domínio informado."""
    # 1. Tentar via win32security.DsGetDcName (Active Directory via DNS)
    try:
        import win32security
        if hasattr(win32security, "DsGetDcName"):
            dc_info = win32security.DsGetDcName(domainName=domain)
            if dc_name := dc_info.get("DomainControllerName"):
                return dc_name
    except Exception:
        pass

    # 2. Tentar via win32net.NetGetAnyDCName (NetBIOS / SAM)
    try:
        import win32net
        if hasattr(win32net, "NetGetAnyDCName"):
            return win32net.NetGetAnyDCName(None, domain)
    except Exception:
        pass

    # 3. Tentar via win32net.NetGetDCName
    try:
        import win32net
        if hasattr(win32net, "NetGetDCName"):
            return win32net.NetGetDCName(None, domain)
    except Exception:
        pass

    return None


def _fetch_group_members_raw(
    server: str | None,
    group_name: str,
    sid_type: Any = None,
) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """Tenta consultar os membros de um grupo no servidor especificado.

    Alterna entre NetGroupGetUsers (para grupos globais) e NetLocalGroupGetMembers
    (para grupos locais de máquina e grupos locais de domínio/alias), tratando
    a hierarquia conforme o tipo de SID informado.
    """
    import win32net

    errors: list[str] = []
    server_label = server or "padrão"

    # SidTypeAlias (valor 4 ou string 'SidTypeAlias') representa grupos locais
    # e grupos locais de domínio (Domain Local Groups). Nesses casos, NetLocalGroupGetMembers é prioritário.
    is_alias = sid_type in ("SidTypeAlias", 4)

    def try_local_group_members() -> list[dict[str, Any]] | None:
        if not hasattr(win32net, "NetLocalGroupGetMembers"):
            return None
        # A API NetLocalGroupGetMembers aceita níveis 2, 1, 3 e 0
        for level in (2, 1, 3, 0):
            try:
                members, _, _ = win32net.NetLocalGroupGetMembers(server, group_name, level)
                return members
            except Exception as exc:
                errors.append(f"servidor={server_label}, nível={level} (LocalGroup): {exc}")
        return None

    def try_group_users() -> list[dict[str, Any]] | None:
        if not hasattr(win32net, "NetGroupGetUsers"):
            return None
        # NetGroupGetUsers aceita somente níveis 1 e 0
        for level in (1, 0):
            try:
                members, _, _ = win32net.NetGroupGetUsers(server, group_name, level)
                return members
            except Exception as exc:
                errors.append(f"servidor={server_label}, nível={level} (Group): {exc}")
        return None

    methods = [try_local_group_members, try_group_users] if is_alias else [try_group_users, try_local_group_members]

    for method in methods:
        members = method()
        if members is not None:
            return members, errors

    return None, errors


def list_group_members(group: str, sid_type: Any = None) -> list[str]:
    """Retorna os membros diretos de um grupo no formato DOMINIO\\Usuario.

    Suporta grupos globais, de domínio local e locais do Windows/Active Directory.
    """
    try:
        import win32net
    except ImportError:
        return []

    if "\\" in group:
        domain, group_name = group.split("\\", 1)
    else:
        domain = ""
        group_name = group

    candidate_servers: list[str | None] = [None]

    if domain:
        dc_name = _find_domain_controller(domain)
        if dc_name and dc_name not in candidate_servers:
            candidate_servers.append(dc_name)

        unc_domain = f"\\\\{domain}" if not domain.startswith("\\\\") else domain
        if unc_domain not in candidate_servers:
            candidate_servers.append(unc_domain)
        if domain not in candidate_servers:
            candidate_servers.append(domain)

    all_errors: list[str] = []
    raw_members: list[dict[str, Any]] | None = None

    for server in candidate_servers:
        raw_members, errors = _fetch_group_members_raw(server, group_name, sid_type)
        if raw_members is not None:
            break
        all_errors.extend(errors)

    if raw_members is None:
        raise RuntimeError(
            f"não foi possível consultar os membros de {group} ({'; '.join(all_errors)})"
        )

    result: list[str] = []
    for member in raw_members:
        # NetLocalGroupGetMembers (níveis 2 e 3) retorna 'domainandname'
        # NetGroupGetUsers (nível 1 e 0) retorna 'name' ou 'username'
        name = (
            member.get("domainandname")
            or member.get("username")
            or member.get("name")
        )
        if not name and "sid" in member:
            try:
                import win32security
                acc_name, acc_domain, _ = win32security.LookupAccountSid(None, member["sid"])
                name = f"{acc_domain}\\{acc_name}" if acc_domain else acc_name
            except Exception:
                name = str(member["sid"])

        if name:
            if "\\" in name:
                result.append(name)
            elif domain:
                result.append(f"{domain}\\{name}")
            else:
                result.append(name)

    return result


def list_groups(path: str) -> list[dict[str, Any]]:
    """Lê a DACL da pasta e retorna a lista de grupos com permissões e membros resolvidos.

    Extrai os grupos encontrados nas ACEs (Access Control Entries), converte SIDs
    em nomes legíveis e consulta os membros de cada grupo encontrado.
    """
    try:
        import win32security
    except ImportError as exc:
        raise RuntimeError(
            "Execute no Windows após instalar pywin32: python -m pip install pywin32"
        ) from exc

    descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return []

    sid_type_names = {
        key: value for key, value in vars(win32security).items()
        if key.startswith("SidType") and isinstance(value, int)
    }
    result: list[dict[str, Any]] = []
    for index in range(dacl.GetAceCount()):
        header, mask, sid = dacl.GetAce(index)[:3]
        ace_type, ace_flags = header
        name, domain, sid_type = win32security.LookupAccountSid(None, sid)
        sid_type_name = sid_type_names.get(sid_type, SID_TYPE_NAMES.get(sid_type, str(sid_type)))
        if not is_group_account(sid_type_name):
            continue

        group = f"{domain}\\{name}" if domain else name
        try:
            members = list_group_members(group, sid_type=sid_type_name)
            members_error = ""
        except RuntimeError as exc:
            members = []
            members_error = str(exc)

        # Tipos de ACE de negação: ACCESS_DENIED_ACE_TYPE (1) e ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE (6)
        result.append({
            "grupo": group,
            "sid": str(sid),
            "tipo": "NEGAR" if ace_type in (1, 6) else "PERMITIR",
            "permissoes": permission_names(mask),
            "herdada": is_inherited_ace(ace_flags),
            "membros": members,
            "membros_erro": members_error,
        })
    return collapse_group_permissions(result)


# =====================================================================
# Geração do Relatório Excel (openpyxl)
# =====================================================================

def _sheet_title(group: str, used_titles: set[str]) -> str:
    """Gera um nome de aba válido para o Excel (máx 31 caracteres, sem caracteres proibidos)."""
    title = group.rsplit("\\", 1)[-1]
    for invalid in r"\/*?:[]":
        title = title.replace(invalid, "_")
    title = (title or "Grupo")[:31]
    candidate = title
    suffix = 2
    while candidate.casefold() in {item.casefold() for item in used_titles}:
        suffix_text = f" ({suffix})"
        candidate = f"{title[:31 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    return candidate


def write_excel(entries: list[dict[str, Any]], output: str | Path) -> None:
    """Gera a planilha Excel (.xlsx) com a aba resumo 'Grupos' e abas individuais por grupo."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError as exc:
        raise RuntimeError("Instale a dependência do Excel: python -m pip install openpyxl") from exc

    workbook = Workbook()

    # Aba de resumo: lista geral de grupos e permissões consolidadas
    summary = workbook.active
    summary.title = "Grupos"
    summary.append(["Nome do grupo", "Permissão"])

    for entry in entries:
        action = "Permitir" if entry.get("tipo") == "PERMITIR" else "Negar"
        label = permission_label(entry.get("permissoes", []))
        summary.append([entry["grupo"], f"{action} - {label}"])

    for cell in summary[1]:
        cell.font = Font(bold=True)
    summary.freeze_panes = "A2"
    summary.column_dimensions["A"].width = 45
    summary.column_dimensions["B"].width = 35

    # Agrupa membros únicos por grupo mantendo a ordem original
    groups: dict[str, list[str]] = {}
    for entry in entries:
        group = entry.get("grupo", "")
        groups.setdefault(group, [])
        members = entry.get("membros", entry.get("members", [])) or []
        if isinstance(members, str):
            members = [members]
        for member in members:
            if member not in groups[group]:
                groups[group].append(member)

    used_titles = {summary.title}
    for group, members in groups.items():
        sheet = workbook.create_sheet(_sheet_title(group, used_titles))
        used_titles.add(sheet.title)
        sheet.append([group])
        for member in members:
            sheet.append([member])

        # Registra erros eventuais de consulta de membros para fins de auditoria
        if entry_error := next(
            (entry.get("membros_erro") for entry in entries
             if entry.get("grupo") == group and entry.get("membros_erro")),
            "",
        ):
            sheet.append([f"ERRO: {entry_error}"])

        sheet["A1"].font = Font(bold=True)
        sheet.column_dimensions["A"].width = 45

    workbook.save(output)


def output_path_for_folder(folder: str | Path) -> Path:
    """Retorna o caminho padrão da planilha Excel dentro da pasta analisada."""
    return Path(folder) / DEFAULT_OUTPUT_NAME


def process_folder(folder: str | Path, output: str | Path | None = None) -> Path:
    """Analisa as permissões de uma pasta e gera a planilha Excel correspondente."""
    folder_path = Path(folder)
    output_path = Path(output) if output is not None else output_path_for_folder(folder_path)
    entries = list_groups(str(folder_path))
    write_excel(entries, output_path)
    return output_path


# =====================================================================
# Interface Gráfica (Tkinter)
# =====================================================================

def run_gui() -> None:
    """Abre a interface gráfica (Tkinter) para seleção de pasta e geração da planilha."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except ImportError as exc:
        raise RuntimeError("Tkinter não está disponível nesta instalação do Python.") from exc

    root = tk.Tk()
    root.title("Listar Grupos e Permissões")
    root.resizable(False, False)

    folder_var = tk.StringVar()
    output_var = tk.StringVar()
    status_var = tk.StringVar(value="Selecione uma pasta para começar.")

    frame = tk.Frame(root, padx=18, pady=18)
    frame.grid(sticky="nsew")

    tk.Label(frame, text="Pasta a analisar (local ou rede SMB):").grid(row=0, column=0, sticky="w")
    folder_entry = tk.Entry(frame, textvariable=folder_var, width=62)
    folder_entry.grid(row=1, column=0, padx=(0, 8), pady=(4, 12))

    def choose_folder() -> None:
        selected = filedialog.askdirectory(title="Selecione a pasta a analisar")
        if selected:
            folder_var.set(selected)
            output_var.set(str(output_path_for_folder(selected)))
            status_var.set("Pasta selecionada. Clique em 'Gerar planilha'.")

    tk.Button(frame, text="Procurar...", command=choose_folder, width=12).grid(
        row=1, column=1, pady=(4, 12)
    )

    tk.Label(frame, text="Arquivo de saída:").grid(row=2, column=0, sticky="w")
    tk.Label(frame, textvariable=output_var, anchor="w", width=62).grid(
        row=3, column=0, columnspan=2, sticky="w", pady=(4, 12)
    )

    def generate() -> None:
        folder = folder_var.get().strip()
        if not folder:
            messagebox.showwarning(
                "Pasta não informada",
                "Selecione ou informe o diretório da pasta.",
                parent=root,
            )
            folder_entry.focus_set()
            return

        if not Path(folder).is_dir():
            messagebox.showerror(
                "Pasta inválida",
                "O diretório informado não existe ou não é uma pasta acessível.",
                parent=root,
            )
            return

        status_var.set("Processando permissões e membros... Aguarde.")
        root.update_idletasks()

        try:
            output = process_folder(folder)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Erro ao gerar planilha", str(exc), parent=root)
            status_var.set("Ocorreu um erro durante a leitura.")
            return

        output_var.set(str(output))
        status_var.set(f"Concluído: {output}")
        messagebox.showinfo("Concluído", f"Planilha criada em:\n{output}", parent=root)

    tk.Button(frame, text="Gerar planilha", command=generate, width=18).grid(
        row=4, column=0, columnspan=2, pady=(2, 10)
    )
    tk.Label(frame, textvariable=status_var, fg="#555", wraplength=520, justify="left").grid(
        row=5, column=0, columnspan=2, sticky="w"
    )

    folder_entry.focus_set()
    root.mainloop()


# =====================================================================
# Linha de Comando (CLI) e Ponto de Entrada Principal
# =====================================================================

def main(argv: list[str] | None = None) -> None:
    """Executa a aplicação via linha de comando ou abre a interface gráfica se nenhum argumento for fornecido."""
    argv = sys.argv[1:] if argv is None else argv

    # Se invocado sem argumentos na linha de comando, inicia a interface gráfica
    if not argv:
        run_gui()
        return

    parser = argparse.ArgumentParser(
        description="Lista grupos presentes na ACL de uma pasta Windows/SMB e exporta para Excel.",
    )
    parser.add_argument(
        "pasta",
        nargs="?",
        default=None,
        help="Caminho da pasta local ou compartilhamento SMB (ex: \\\\servidor\\pasta)",
    )
    parser.add_argument(
        "-o",
        "--saida",
        default=None,
        help=f"Caminho do arquivo Excel gerado (padrão: <pasta>/{DEFAULT_OUTPUT_NAME})",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Abre a interface gráfica (Tkinter)",
    )

    args = parser.parse_args(argv)

    if args.gui:
        run_gui()
        return

    if not args.pasta:
        parser.error("Informe o caminho da pasta a ser analisada ou use --gui para abrir a interface.")

    output_target = Path(args.saida) if args.saida else output_path_for_folder(args.pasta)

    try:
        entries = list_groups(args.pasta)
    except (OSError, RuntimeError) as exc:
        parser.error(str(exc))

    write_excel(entries, output_target)
    print(f"Planilha criada: {output_target.resolve()}")
    print(f"Grupos encontrados: {len(entries)}")


if __name__ == "__main__":
    main()
