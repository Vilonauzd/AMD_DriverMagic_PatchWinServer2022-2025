# DevTurtle Proposed Modular Scaffold Groupings

Basis: `devturtle_GITHUB_REPO_INVENTORY_CONTEXT_HELPER_QA.py`
SHA-256: `1c7acdd7d844891ab5e6a200124f0d8ee33db08747019de8c7889cf280765d28`
Inventory: 65 classes, 711 functions/methods, 776 definitions total.

This is a grouping/scaffold proposal only. It does not alter source behavior.

## Porting rule

For the first modularization pass, move whole definitions unchanged. Do not split methods out of large classes, rename public symbols, rewrite imports for elegance, or refactor behavior at the same time. Keep a compatibility `devturtle/__init__.py` (or top-level `devturtle.py` facade during transition) that re-exports the existing public API.

## 1. `devturtle/core/` — configuration, runtime identity, contracts

**Definitions**
- `RuntimePlatform`
- `Phase`
- `RejectionReason`
- `ControlMode`
- `ControllerProfile`
- `ResponseContract`
- `RecoveryMessages`

**Top-level functions/constants**
- `_deep_merge`
- `load_config`
- `save_config`
- `configure_logging`
- `detect_runtime_platform`
- `runtime_platform_value`
- `runtime_default_shell`
- `runtime_shell_enum`
- `runtime_shell_description`
- `runtime_path_violation_message`
- `runtime_discovery_commands`
- `runtime_environment_hint`
- `runtime_controller_profile_label`
- `runtime_controller_profile_doctrine`
- `CONFIG_PATH`, `DEFAULT_CONFIG`, `CONFIG`, build/version constants

**Likely files**
- `core/config.py`
- `core/runtime.py`
- `core/contracts.py`

## 2. `devturtle/persistence/` — sessions, durable event ledger, logging bridge

**Definitions**
- `SessionManager`
- `OperationalEventLedger`
- `CallbackOperationalEventLedger`
- `OperationalEventLoggingHandler`

**Likely files**
- `persistence/session.py`
- `persistence/ledger.py`

## 3. `devturtle/security/` — credential safety and global policy registry

**Definitions**
- `CredentialSafetyController`
- `PolicyRegistry`

**Likely files**
- `security/credentials.py`
- `security/policy.py`

Connector-specific command policies stay with their connectors rather than in this package.

## 4. `devturtle/state/` — authoritative run state and observed state

**Definitions**
- `RunState`
- `ReboundVault`
- `StateObserver`
- `AuthoritativeStateLedger`

**Likely files**
- `state/run_state.py`
- `state/rebound.py`
- `state/observation.py`

`RunState` should remain one intact class during the first port even though it is large.

## 5. `devturtle/context/` — discovery, continuity, memory, history, epochs

**Definitions**
- `DiscoveryEngine`
- `CTSEngine`
- `ProjectMemoryController`
- `TrajectoryController`
- `ConversationJournalController`
- `ConversationArchiveController`
- `WorkingMemoryBuilder`
- `HistorySearchController`
- `ContextEpochController`

**Likely files**
- `context/discovery.py`
- `context/cts.py`
- `context/project_memory.py`
- `context/trajectory.py`
- `context/journal.py`
- `context/archive.py`
- `context/working_memory.py`
- `context/history_search.py`
- `context/epochs.py`

This is one architectural bounded context: durable continuity plus the exact context projected to the model.

## 6. `devturtle/connectors/` — GitLab/GitHub integration and capability context

**Definitions**
- `GitLabCommandPolicy`
- `GitLabContextBuilder`
- `GitHubCommandPolicy`
- `GitHubContextBuilder`
- `GitHubCliAuthenticator`

**Likely files**
- `connectors/gitlab.py`
- `connectors/github.py`

Keep connector authentication, non-secret persisted identity, command safety, and model-facing connector context together by provider.

## 7. `devturtle/skills/` — skill repository, trust, sync, context, builder runtime

**Definitions**
- `SkillValidationFinding`
- `SkillRepository`
- `SkillGitLabSync`
- `SkillContextBuilder`
- `SkillBuilderRuntime`

**Likely files**
- `skills/repository.py`
- `skills/gitlab_sync.py`
- `skills/context.py`
- `skills/builder.py`

## 8. `devturtle/execution/terminal/` — authoritative PTY and shell execution

**Definitions**
- `PersistentTaskTerminal`
- `RuntimeShellLibrary`
- `WindowsShellLibrary`
- `ToolResultTransport`

**Likely files**
- `execution/terminal.py`
- `execution/shell.py`
- `execution/tool_results.py`

`PersistentTaskTerminal` remains intact. It is a critical execution boundary and should not be decomposed during the move.

## 9. `devturtle/execution/authoring/` — semantic authoring, inspection, write transport

**Definitions**
- `FileOperationController`
- `SemanticPtyAuthoringController`
- `SemanticPtyInspectionController`
- `TargetedFailureReceiptController`
- `WriteTransportState`
- `WriteTransportController`

**Top-level helper**
- `_is_meta_artifact`

**Likely files**
- `execution/file_operations.py`
- `execution/semantic_authoring.py`
- `execution/semantic_inspection.py`
- `execution/failure_receipts.py`
- `execution/write_transport.py`

## 10. `devturtle/verification/` — proof, completion, runtime and functional verification

**Definitions**
- `ObservedWriteEpochController`
- `RuntimeCompletionValidator`
- `ActionVerifyController`
- `WindowsOpsVerificationController`
- `FunctionalVerificationController`
- `SuccessCriteriaEvaluator`

**Likely files**
- `verification/write_epochs.py`
- `verification/runtime.py`
- `verification/action.py`
- `verification/windows_ops.py`
- `verification/functional.py`
- `verification/success.py`

## 11. `devturtle/control/` — phase, focus, long-horizon control, steering, loop control

**Definitions**
- `PhaseController`
- `MechanicalFocusController`
- `LongHorizonController`
- `OperatorSteeringQueueController`
- `InferenceStepController`
- `ErrorClassifier`
- `LoopGuard`

**Likely files**
- `control/phase.py`
- `control/focus.py`
- `control/long_horizon.py`
- `control/steering.py`
- `control/inference_step.py`
- `control/errors.py`
- `control/loop_guard.py`

## 12. `devturtle/llm/` — provider-stream assembly and model-output governance

**Definitions**
- `PromptContractQA`
- `GenerationQualityCheck`
- `BabbleWatchdog`
- `ReasoningGovernance`
- `LLMStreamAssembler`

**Likely files**
- `llm/contracts.py`
- `llm/quality.py`
- `llm/watchdog.py`
- `llm/reasoning.py`
- `llm/stream.py`

## 13. `devturtle/orchestration/` — composition root and public run entrypoint

**Definitions**
- `AutomationOrchestrator`

**Top-level function**
- `run_task`

**Likely files**
- `orchestration/orchestrator.py`
- `orchestration/entrypoint.py`

`AutomationOrchestrator` should initially remain intact as the composition root. Once the modular port is proven byte/behavior-compatible, its internal responsibilities can be evaluated separately; they should not be refactored during the migration itself.

---

# Suggested package shape

```text
devturtle/
├── __init__.py                 # compatibility facade / re-exports
├── core/
│   ├── config.py
│   ├── runtime.py
│   └── contracts.py
├── persistence/
│   ├── session.py
│   └── ledger.py
├── security/
│   ├── credentials.py
│   └── policy.py
├── state/
│   ├── run_state.py
│   ├── rebound.py
│   └── observation.py
├── context/
│   ├── discovery.py
│   ├── cts.py
│   ├── project_memory.py
│   ├── trajectory.py
│   ├── journal.py
│   ├── archive.py
│   ├── working_memory.py
│   ├── history_search.py
│   └── epochs.py
├── connectors/
│   ├── gitlab.py
│   └── github.py
├── skills/
│   ├── repository.py
│   ├── gitlab_sync.py
│   ├── context.py
│   └── builder.py
├── execution/
│   ├── terminal.py
│   ├── shell.py
│   ├── tool_results.py
│   ├── file_operations.py
│   ├── semantic_authoring.py
│   ├── semantic_inspection.py
│   ├── failure_receipts.py
│   └── write_transport.py
├── verification/
│   ├── write_epochs.py
│   ├── runtime.py
│   ├── action.py
│   ├── windows_ops.py
│   ├── functional.py
│   └── success.py
├── control/
│   ├── phase.py
│   ├── focus.py
│   ├── long_horizon.py
│   ├── steering.py
│   ├── inference_step.py
│   ├── errors.py
│   └── loop_guard.py
├── llm/
│   ├── contracts.py
│   ├── quality.py
│   ├── watchdog.py
│   ├── reasoning.py
│   └── stream.py
└── orchestration/
    ├── orchestrator.py
    └── entrypoint.py
```

# Migration boundary recommendation

The safest first port is a **mechanical module extraction**, not a refactor:

1. Freeze the current source hash.
2. Create package files.
3. Move whole classes/functions unchanged into the mapped modules.
4. Keep names/signatures/behavior unchanged.
5. Add a compatibility facade that re-exports the exact existing public symbols used by Qt and other callers.
6. Run AST inventory comparison: 776 source definitions accounted for, with no missing definitions.
7. Run import graph/cycle validation.
8. Run full existing QA against both monolith and modular build.
9. Compare externally visible config/session/ledger/PTY/context behavior.
10. Only after parity is proven consider decomposing the large classes internally.

The highest-risk classes to leave whole during the initial port are `AutomationOrchestrator`, `RunState`, `PersistentTaskTerminal`, `WriteTransportState`, `LongHorizonController`, and `WorkingMemoryBuilder`.
