# H4 acceptance fixture: unknown root field

**Goal:** Prove the real pack inspector rejects an unknown root field.

**Architecture:** Task 1 writes one file; the JSON root carries `hostHint`.

**Tech Stack:** Rust, Git

**Spec:** docs/sdd/specs/2026-11-15-h4-acceptance-design.md

## Global Constraints

- Keep the approved scope exact.

```sdd-execution-v1
{
  "schema": "sdd-execution-plan",
  "version": 1,
  "hostHint": "widens the schema",
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
      "writePaths": ["src/unknown-field.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/unknown-field.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "written",
          "title": "The file is written",
          "rubric": "src/unknown-field.txt exists.",
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

Write `src/unknown-field.txt`.
