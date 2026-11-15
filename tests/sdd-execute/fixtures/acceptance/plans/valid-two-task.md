# H4 acceptance fixture: two Tasks

**Goal:** Prove two hand-authored Tasks are accepted by the real pack inspector.

**Architecture:** Task 1 writes one file; Task 2 writes a second file and depends on Task 1.

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
      "writePaths": ["src/task-one.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/task-one.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "one-produced",
          "title": "Task one produced its file",
          "rubric": "src/task-one.txt exists with the recorded content.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "one-check",
          "conditionId": "one-produced",
          "description": "The first fixture check passes.",
          "command": "true",
          "cwd": ".",
          "timeoutSeconds": 30,
          "inputPaths": []
        }
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    },
    {
      "number": 2,
      "dependsOn": [1],
      "specRefs": [
        {
          "source": "project",
          "path": "docs/sdd/specs/2026-11-15-h4-acceptance-design.md",
          "sections": ["Contract"]
        }
      ],
      "readPaths": ["src/lib.rs", "src/task-one.txt"],
      "writePaths": ["src/task-two.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/task-two.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "two-produced",
          "title": "Task two produced its file",
          "rubric": "src/task-two.txt exists with the recorded content.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "two-check",
          "conditionId": "two-produced",
          "description": "The final fixture check passes.",
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
  "finalChecks": ["two-check"]
}
```

## File structure

One file per Task under `src/`.

## Task 1: Write the first file

Write `src/task-one.txt` with the recorded content.

## Task 2: Write the second file

Write `src/task-two.txt` with the recorded content.
