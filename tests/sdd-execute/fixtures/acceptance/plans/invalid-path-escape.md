# H4 acceptance fixture: path escape

**Goal:** Prove the real pack inspector rejects a write path that escapes the project.

**Architecture:** Task 1 declares `../outside.txt` as a write path and deliverable.

**Tech Stack:** Rust, Git

**Spec:** docs/sdd/specs/2026-11-15-h4-acceptance-design.md

## Global Constraints

- Keep the approved scope exact.

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
      "writePaths": ["../outside.txt"],
      "allowShell": false,
      "deliverables": [{"path": "../outside.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "written",
          "title": "The file is written",
          "rubric": "../outside.txt exists.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "written-check",
          "conditionId": "written",
          "description": "The fixture check passes.",
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
  "finalChecks": ["written-check"]
}
```

## Task 1: Write the file

Write `../outside.txt`.
