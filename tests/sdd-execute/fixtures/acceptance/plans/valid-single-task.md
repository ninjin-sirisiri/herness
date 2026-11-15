# H4 acceptance fixture: one Task

**Goal:** Prove a hand-authored single-Task plan is accepted by the real pack inspector.

**Architecture:** Task 1 writes one file; no later Task depends on it.

**Tech Stack:** Rust, Git

**Spec:** docs/sdd/specs/2026-11-15-h4-acceptance-design.md

## Global Constraints

- Keep the approved scope exact.
- The fixture never runs a check, a model, or Git.

```sdd-execution-v1
{
  "schema": "sdd-execution-plan",
  "version": 1,
  "specRefs": [
    {
      "source": "project",
      "path": "docs/sdd/specs/2026-11-15-h4-acceptance-design.md",
      "sections": ["Contract"]
    }
  ],
  "tasks": [
    {
      "number": 1,
      "dependsOn": [],
      "specRefs": [
        {
          "source": "project",
          "path": "docs/sdd/specs/2026-11-15-h4-acceptance-design.md",
          "sections": ["Contract"]
        }
      ],
      "readPaths": ["src/lib.rs"],
      "writePaths": ["src/single.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/single.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "single-produced",
          "title": "The single Task produced its file",
          "rubric": "src/single.txt exists with the recorded content.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "single-check",
          "conditionId": "single-produced",
          "description": "The single fixture check passes.",
          "command": "true",
          "cwd": ".",
          "timeoutSeconds": 30,
          "inputPaths": []
        }
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    }
  ],
  "finalChecks": ["single-check"]
}
```

## File structure

One file under `src/`.

## Task 1: Write the single file

Write `src/single.txt` with the recorded content.
