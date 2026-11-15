# H4 acceptance fixture: broken execution fence

**Goal:** Prove the real pack inspector rejects an execution block whose fence never closes.

**Architecture:** Task 1 writes one file; the closing fence line is absent.

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
      "writePaths": ["src/broken-fence.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/broken-fence.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "written",
          "title": "The file is written",
          "rubric": "src/broken-fence.txt exists.",
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

## Task 1: Write the file

Write `src/broken-fence.txt`.
