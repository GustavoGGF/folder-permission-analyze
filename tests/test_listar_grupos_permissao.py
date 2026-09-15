import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from listar_grupos_permissao import (
    collapse_group_permissions,
    is_group_account,
    is_inherited_ace,
    main,
    output_path_for_folder,
    permission_label,
    permission_names,
    process_folder,
    write_excel,
)


class ListarGruposPermissaoTests(unittest.TestCase):
    def test_script_de_empacotamento_usa_a_pasta_do_proprio_script(self):
        script = Path(__file__).parents[1] / "gerar_exe.bat"
        content = script.read_text(encoding="utf-8")

        self.assertIn('cd /d "%~dp0"', content)
        self.assertIn('if errorlevel 1 goto :erro', content)

    def test_identifica_tipos_de_conta_de_grupo(self):
        self.assertTrue(is_group_account("SidTypeGroup"))
        self.assertTrue(is_group_account("SidTypeDomainGroup"))
        self.assertTrue(is_group_account("SidTypeAlias"))
        self.assertFalse(is_group_account("SidTypeUser"))

    def test_converte_mascara_em_permissoes_legiveis(self):
        self.assertEqual(
            permission_names(0x120089),
            ["READ", "READ_CONTROL", "SYNCHRONIZE"],
        )

    def test_identifica_ace_herdada(self):
        self.assertTrue(is_inherited_ace(0x10))
        self.assertFalse(is_inherited_ace(0x00))

    def test_ignora_admins_do_dominio_e_mantem_so_maior_permissao(self):
        entries = collapse_group_permissions([
            {"grupo": "DOMINIO\\Equipe", "sid": "S-1-1", "tipo": "PERMITIR",
             "permissoes": ["READ"]},
            {"grupo": "DOMINIO\\Equipe", "sid": "S-1-1", "tipo": "PERMITIR",
             "permissoes": ["MODIFY"]},
            {"grupo": "DOMINIO\\Admins. do domínio", "sid": "S-1-2", "tipo": "PERMITIR",
             "permissoes": ["FULL_CONTROL"]},
        ])

        self.assertEqual(entries, [{
            "grupo": "DOMINIO\\Equipe", "sid": "S-1-1", "tipo": "PERMITIR",
            "permissoes": ["MODIFY"],
        }])

    def test_considera_leitura_e_escrita_como_modificacao(self):
        entries = collapse_group_permissions([{
            "grupo": "DOMINIO\\Equipe",
            "tipo": "PERMITIR",
            "permissoes": ["READ", "WRITE"],
        }])

        self.assertEqual(entries[0]["permissoes"], ["MODIFY"])

    def test_preserva_controle_total_acima_de_modificacao(self):
        entries = collapse_group_permissions([{
            "grupo": "DOMINIO\\Equipe",
            "tipo": "PERMITIR",
            "permissoes": ["READ", "WRITE", "DELETE", "WRITE_DAC", "WRITE_OWNER"],
        }])

        self.assertEqual(entries[0]["permissoes"], ["FULL_CONTROL"])

    def test_converte_permissoes_tecnicas_em_texto_simples(self):
        self.assertEqual(
            permission_label(["READ", "EXECUTE", "READ_CONTROL", "SYNCHRONIZE"]),
            "Leitura",
        )
        self.assertEqual(permission_label(["MODIFY"]), "Modificar")
        self.assertEqual(permission_label(["FULL_CONTROL"]), "Controle total")

    def test_gera_planilha_com_grupo_na_coluna_a_e_permissao_na_b(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "resultado.xlsx"
            write_excel([{
                "grupo": "DOMINIO\\Engenharia",
                "tipo": "PERMITIR",
                "permissoes": ["READ", "READ_CONTROL", "SYNCHRONIZE"],
            }], output)

            import openpyxl
            sheet = openpyxl.load_workbook(output, read_only=True).active
            self.assertEqual(list(sheet.values), [
                ("Nome do grupo", "Permissão"),
                ("DOMINIO\\Engenharia", "Permitir - Leitura"),
            ])

    def test_gera_uma_aba_por_grupo_com_seus_membros(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "resultado.xlsx"
            write_excel([
                {
                    "grupo": "DOMINIO\\Engenharia",
                    "tipo": "PERMITIR",
                    "permissoes": ["READ"],
                    "membros": ["DOMINIO\\Ana", "DOMINIO\\Bruno"],
                },
                {
                    "grupo": "DOMINIO\\Financeiro",
                    "tipo": "PERMITIR",
                    "permissoes": ["READ"],
                    "membros": ["DOMINIO\\Carla"],
                },
            ], output)

            import openpyxl
            workbook = openpyxl.load_workbook(output, read_only=True)

            self.assertEqual(
                list(workbook["Engenharia"].values),
                [("DOMINIO\\Engenharia",), ("DOMINIO\\Ana",), ("DOMINIO\\Bruno",)],
            )
            self.assertEqual(
                list(workbook["Financeiro"].values),
                [("DOMINIO\\Financeiro",), ("DOMINIO\\Carla",)],
            )

    def test_consulta_membros_de_um_grupo_de_dominio(self):
        class FakeWin32Net:
            @staticmethod
            def NetGroupGetUsers(domain, group, level):
                self.assertEqual((domain, group), (None, "Equipe"))
                if level == 1:
                    return ([{"name": "Ana"}, {"name": "Bruno"}], 2, 0)
                raise RuntimeError("nível inválido")

        with patch.dict("sys.modules", {"win32net": FakeWin32Net}):
            from listar_grupos_permissao import list_group_members

            self.assertEqual(
                list_group_members("DOMINIO\\Equipe"),
                ["DOMINIO\\Ana", "DOMINIO\\Bruno"],
            )

    def test_consulta_membros_de_grupo_local_de_dominio_com_fallback(self):
        class FakeWin32Net:
            @staticmethod
            def NetGroupGetUsers(server, group, level):
                raise RuntimeError("(2220, 'NetGroupGetUsers', 'Não foi possível localizar o nome de grupo.')")

            @staticmethod
            def NetLocalGroupGetMembers(server, group, level):
                if level == 2:
                    return ([{"domainandname": "DOMINIO\\Carlos"}], 1, 0)
                raise RuntimeError("nível inválido")

        with patch.dict("sys.modules", {"win32net": FakeWin32Net}):
            from listar_grupos_permissao import list_group_members

            self.assertEqual(
                list_group_members("DOMINIO\\FS - TI"),
                ["DOMINIO\\Carlos"],
            )

    def test_consulta_membros_com_descoberta_de_controlador_de_dominio(self):
        class FakeWin32Net:
            @staticmethod
            def NetGetAnyDCName(server, domain):
                return r"\\DC01"

            @staticmethod
            def NetGroupGetUsers(server, group, level):
                if server == r"\\DC01" and level == 1:
                    return ([{"name": "Diana"}], 1, 0)
                raise RuntimeError("não localizado")

        with patch.dict("sys.modules", {"win32net": FakeWin32Net}):
            from listar_grupos_permissao import list_group_members

            self.assertEqual(
                list_group_members("DOMINIO\\EquipeDC"),
                ["DOMINIO\\Diana"],
            )

    def test_define_planilha_padrao_na_pasta_informada(self):
        self.assertEqual(
            output_path_for_folder(r"C:\Dados\Compartilhado"),
            Path(r"C:\Dados\Compartilhado") / "grupos_permissoes.xlsx",
        )

    def test_processa_pasta_e_salva_planilha(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            expected_output = folder / "grupos_permissoes.xlsx"
            entries = [{"grupo": "DOMINIO\\Equipe", "tipo": "PERMITIR", "permissoes": ["READ"]}]

            with patch("listar_grupos_permissao.list_groups", return_value=entries) as list_mock:
                with patch("listar_grupos_permissao.write_excel") as write_mock:
                    result = process_folder(folder)

            list_mock.assert_called_once_with(str(folder))
            write_mock.assert_called_once_with(entries, expected_output)
            self.assertEqual(result, expected_output)

    def test_main_abre_gui_se_sem_argumentos(self):
        with patch("listar_grupos_permissao.run_gui") as gui_mock:
            main([])
            gui_mock.assert_called_once()

    def test_main_abre_gui_com_flag_gui(self):
        with patch("listar_grupos_permissao.run_gui") as gui_mock:
            main(["--gui"])
            gui_mock.assert_called_once()

    def test_main_executa_cli_e_gera_planilha(self):
        with patch("listar_grupos_permissao.list_groups", return_value=[]) as list_mock:
            with patch("listar_grupos_permissao.write_excel") as write_mock:
                main([r"\\servidor\compartilhado", "-o", "saida.xlsx"])
                list_mock.assert_called_once_with(r"\\servidor\compartilhado")
                write_mock.assert_called_once_with([], Path("saida.xlsx"))


if __name__ == "__main__":
    unittest.main()
