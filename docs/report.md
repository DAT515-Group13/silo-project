# Project Report: [Project Name]

> Keep this report concise and practical. Replace all bracketed text and remove
> these instructions before submission. Do not repeat the design document;
> describe only the delivered result and material changes from the approved plan.

## 1. Project and Submission

- **Repository:** [URL]
- **Deployed application or endpoint:** [URL, access instructions, or N/A]
- **Mentor:** [name]
- **Group members:** [name, student number, and GitHub username for each member]
- **Report completed:** [YYYY-MM-DD]

In two or three sentences, state what the system does, who it is for, and what
the group delivered.

### Delivered Scope

Report outcomes, not planned activity. Link each claim to the strongest available
evidence, such as a test, source file, deployment manifest, workflow run, or
video timestamp.

| Core goal from `design.md` | Result (met, partial, or not met) | Evidence | Brief explanation |
| -------------------------- | --------------------------------- | -------- | ----------------- |
|                            |                                   |          |                   |

### Changes from the Approved Design

[Summarize material architecture, technology, or scope changes and why they
were made. Write "None" if the implementation follows `design.md`.]

## 2. Reproduce and Verify

Instructions must work from a clean checkout. Prefer scripts, a `Justfile`,
or a `Makefile` over repeated manual steps. State which commands are local
and which create billable cloud resources.

### Prerequisites

List only software or accounts the evaluator must obtain separately.

| Requirement | Tested version | Purpose |
| ----------- | -------------- | ------- |
|             |                |         |

### Configuration

Document required variables and configuration without exposing secrets. Commit
a safe example file when useful.

| Variable or file | Required? | Purpose and example value | Secret? |
| ---------------- | --------- | ------------------------- | ------- |
|                  |           |                           |         |

### Build

```bash
# Exact commands from a clean checkout
```

### Test

```bash
# Exact commands for the relevant automated tests
```

State the expected result and any test that requires separate infrastructure.

### Deploy

```bash
# Exact commands to deploy to the target environment
```

State any one-time setup, expected completion time, and where the deployment can
be observed. If a local deployment is useful for development, document it after
the required target deployment rather than duplicating common steps.

### Verify and Use

```bash
# Minimal commands or requests that prove the deployed system works
```

State the expected output. Include one short representative usage example or
test scenario if it is not already covered by the verification command.

### Stop or Remove Resources

```bash
# Commands that stop services or remove resources that may continue to incur cost
```

## 3. Evaluation Evidence

### Testing

Briefly explain what the automated tests cover, what they intentionally do not
cover, and the result from the submitted revision. Avoid listing test types that
the project does not need.

### Operations and Security

Describe only measures relevant to this system and support them with evidence.
Examples include health checks, logs, metrics, resource limits, recovery,
authentication, authorization, secret handling, and TLS.

| Concern | Implemented measure | Evidence or verification |
| ------- | ------------------- | ------------------------ |
|         |                     |                          |

### Known Limitations and Troubleshooting

List important known limitations and problems an evaluator may realistically
encounter. Give a concise symptom, diagnosis command, and remedy for each. Omit
this section if there are none.

## 4. Accountability

The required self-assessment is in `contributions.md`, and the required time
records are in `hours.csv`. Do not duplicate those records here.
