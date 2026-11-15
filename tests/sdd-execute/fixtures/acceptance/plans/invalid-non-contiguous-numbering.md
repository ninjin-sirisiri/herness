# H4 acceptance fixture: non-contiguous Task numbering

**Goal:** Prove the real pack inspector rejects Task headings that skip a number.

**Architecture:** Two Tasks are declared in JSON, but the Markdown headings say Task 1 and Task 3.

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
      "writePaths": ["src/first.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/first.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "first-written",
          "title": "The first file is written",
          "rubric": "src/first.txt exists.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "first-check",
          "conditionId": "first-written",
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
      "readPaths": ["src/lib.rs", "src/first.txt"],
      "writePaths": ["src/second.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/second.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "second-written",
          "title": "The second file is written",
          "rubric": "src/second.txt exists.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "second-check",
          "conditionId": "second-written",
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
  "finalChecks": ["second-check"]
}
```

## Task 1: Write the first file

Write `src/first.txt`.

## Task 3: Write the second file

Write `src/second.txt`.
