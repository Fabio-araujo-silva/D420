"""Testes mínimos do patcher (unittest puro, sem dependências).

Rodar da raiz do repositório:
    python -m unittest discover -s tests -v
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import patcher  # noqa: E402

# assinatura do stub real (DaVinci Resolve 21.2, fusionsystem.dll),
# usada aqui só como padrão de bytes de teste
SIG = "4c8bc2488bd1488d0d33acff01e9ce941800"
PATCHED = "b801000000c3488d0d33acff01e9ce941800"
STUB_AT = 0x30a830  # offset do stub dentro do arquivo de verdade (aprox. p/ teste)

PROFILE = {
    "_file": "test.toml",
    "version": "test",
    "target": [{
        "file": "fake.dll",
        "name": "IsStudio -> sempre true",
        "sig": SIG,
        "patched": PATCHED,
    }],
}


def make_fake(path: str) -> bytes:
    """Arquivo 'binário' falso: 0x90 em tudo, com o stub em STUB_AT."""
    raw, _ = patcher.parse_sig(SIG)
    data = bytearray(b"\x90" * (STUB_AT + 64))
    data[STUB_AT:STUB_AT + len(raw)] = raw
    with open(path, "wb") as fh:
        fh.write(data)
    return bytes(data)


class PatcherTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ru-test-")
        self.path = os.path.join(self.dir, "fake.dll")
        self.original = make_fake(self.path)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def state(self):
        r = patcher.evaluate(self.dir, PROFILE)
        return r["targets"][0]["state"]

    def test_detecta_original(self):
        self.assertEqual(self.state(), "original")

    def test_ciclo_patch_unpatch(self):
        self.assertEqual(patcher._apply(self.dir, PROFILE, "patched"), 0)
        self.assertEqual(self.state(), "patched")
        self.assertEqual(patcher._apply(self.dir, PROFILE, "original"), 0)
        self.assertEqual(self.state(), "original")
        self.assertEqual(open(self.path, "rb").read(), self.original)

    def test_patch_idempotente(self):
        patcher._apply(self.dir, PROFILE, "patched")
        self.assertEqual(patcher._apply(self.dir, PROFILE, "patched"), 0)
        dados = open(self.path, "rb").read()
        self.assertEqual(len(patcher.find_all(dados, PATCHED)), 1)

    def test_ignora_o_resto_do_mundo(self):
        patcher._apply(self.dir, PROFILE, "patched")
        dados = open(self.path, "rb").read()
        # tudo igual, menos exatamente os 6 primeiros bytes do stub
        diff = [i for i, (a, b) in enumerate(zip(self.original, dados)) if a != b]
        self.assertEqual(diff, list(range(STUB_AT, STUB_AT + 6)))

    def test_assinatura_duplicada_e_ambigua(self):
        raw, _ = patcher.parse_sig(SIG)
        with open(self.path, "ab") as fh:
            fh.write(raw)
        self.assertEqual(self.state(), "ambiguous")
        self.assertEqual(patcher._apply(self.dir, PROFILE, "patched"), 1)

    def test_backup_desconfiado_recusa(self):
        # backup existe mas não contém a assinatura original
        bak = self.path + patcher.BACKUP_SUFFIX
        with open(bak, "wb") as fh:
            fh.write(b"\x00" * 512)
        self.assertEqual(patcher._apply(self.dir, PROFILE, "patched"), 1)
        # nada foi escrito: arquivo segue original
        self.assertEqual(open(self.path, "rb").read(), self.original)

    def test_curinga_na_assinatura(self):
        sig_mask = SIG[:2] + "??" + SIG[4:]
        prof = {**PROFILE, "target": [{**PROFILE["target"][0], "sig": sig_mask}]}
        self.assertEqual(patcher.evaluate(self.dir, prof)["targets"][0]["state"], "original")


if __name__ == "__main__":
    unittest.main()
