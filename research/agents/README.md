# research/agents/

Un archivo por proveedor de IA. Cada agente crea el suyo al iniciar.

## Estado actual

| Proveedor | Archivo | Track | Área | Estado |
|---|---|---|---|---|
| OpenCode (Zen) | `opencode.md` | **A** | Evasión de WAF bajo presupuesto | claimed |
| Claude Code | `claude.md` | **B** | Semántica de parámetros y evidencia causal | claimed |
| Antigravity CLI | `antigravity.md` | **C** | Orquestación multi-agente | claimed (con reserva) |

## Tracks

- **A** — Evasión de WAF bajo presupuesto de requests
- **B** — Semántica de parámetros y evidencia causal
- **C** — Orquestación multi-agente autónoma

Definición completa en `../../AGENTS.md` §2. Procedimiento paso a paso en la
skill correspondiente de `.agents/skills/`.

## Formato de un claim

```markdown
# Claim — <proveedor>  ·  YYYY-MM-DD
Track: A | B | C
Estado: claimed | in-progress | blocked | done

## Área asignada
Una frase.

## Archivos que toco
- ruta/uno.py

## Skills que cargo
- track-x-algo
- experiment-protocol

## Primer paso
Qué bloquea el track hasta que se haga.

## Notas
Una línea por milestone.
```

## Reglas

1. Un archivo tocado por un claim pertenece a ese agente. No lo edites.
2. Si necesitas tocar un archivo de otro track, dilo en tu claim y espera
   confirmación del humano.
3. Escribe la hipótesis pre-registrada (`research/notes/<track>-prereg.md`)
   **antes** de la primera corrida.
4. Corre `experiment-auditor` sobre tus propios números antes de reportarlos.
5. Reasignar un track está permitido: actualiza la tabla de arriba y el
   `AGENTS.md` §2 ter. Solo importa que no haya dos proveedores en el mismo
   track.
