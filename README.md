# resolve-unlocked

O DaVinci Resolve gratuito decide "sou Studio?" de um jeito bem simples: uma
função de 8 bytes, `Fusion::FusionApp::IsStudio()`, que lê um byte-flag e
devolve `true`/`false`. A UI importa essa função pelo nome e usa o resultado
para ligar ou desligar dezenas de recursos da edição paga.

Este projeto vira essa chave com **6 bytes de patch binário** — `mov eax,1; ret`
sobre o stub de entrada da função — localizado por **assinatura de bytes**, não
por offset fixo. Nada de DLL injetada, nada de wrapper, nada de recompilar: o
tamanho do arquivo não muda e o patch é 100% reversível.

## Quick start

```bash
# ver o que está instalado (detecta o perfil pela assinatura)
python patcher.py detect  --dir "C:\Program Files\Blackmagic Design\DaVinci Resolve"

# aplicar (faz backup do .dll no primeiro patch)
python patcher.py patch   --dir "C:\Program Files\Blackmagic Design\DaVinci Resolve"

# conferir / reverter
python patcher.py status  --dir "C:\Program Files\Blackmagic Design\DaVinci Resolve"
python patcher.py unpatch --dir "C:\Program Files\Blackmagic Design\DaVinci Resolve"
```

Requer Python 3.11+ e zero dependências. Feche o Resolve antes de patchear.

## O que o patch faz e o que NÃO faz

Faz:
- `IsStudio()` passa a devolver `true` para quem chama (motor e UI via import).

Não faz (por enquanto — roadmap honesto):
- Não remove a janela/aviso de ativação do startup (o `LicenseMgt` do
  `Resolve.exe` continua existindo).
- Não garante portões de codec/export que morem fora do motor Fusion.
- Não substitui licença para uso comercial. Você estudou o binário; a Blackmagic
  não assinou embaixo.

## Como adicionar suporte a uma versão nova

1. `python patcher.py detect --dir <pasta>` — se disser "nenhum perfil bateu":
2. Abra o binário no Ghidra (ou hex-editor) e localize a entrada exportada
   `?IsStudio@FusionApp@Fusion@@QEAA_NXZ` de `fusionsystem.dll`.
3. Copie os bytes do stub de entrada → campo `sig`; copie os mesmos bytes com
   os 6 primeiros trocados por `b8 01 00 00 00 c3` → campo `patched`.
   (Use `??` para bytes que variam, ex.: deslocamentos rip-relativos.)
4. Guarde o SHA-256 do DLL original no perfil.
5. `patch → status → unpatch → status` numa cópia antes de abrir PR.

## Como funciona a detecção

Cada alvo no perfil tem duas assinaturas: o stub **original** e o stub
**patcheado**. O patcher só age quando uma delas casa **exatamente uma vez** no
arquivo; duas ou zero coincidências = recusa e aviso, nunca patch no chute.
Se o SHA-256 do arquivo diferir do registrado no perfil, o `status` avisa
(o patch ainda pode ser aplicado, mas você está numa build não testada).

## Legal

O Resolve é proprietário; a EULA desaconselha engenharia reversa. Este
repositório distribui **apenas script + perfis** — nenhum byte do binário da
Blackmagic. Use por sua conta e risco, e instale a versão oficial.
