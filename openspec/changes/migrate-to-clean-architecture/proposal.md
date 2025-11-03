# Proposal: Migrate to Clean Architecture

## Why

The codebase currently has **two complete plugin systems running in parallel**, causing significant technical debt:

1. **Legacy System** (`core/`):
   - `plugin_manager.py` (568 lines) - Plugin lifecycle and execution
   - `plugin_loader.py` (1095 lines) - Plugin discovery and loading
   - Used by: CLI entry point (main.py), command handlers, system commands
   - **10 active imports** across CLI and commands

2. **New System** (`application/` + `infrastructure/`):
   - `application/services/plugin_service.py` (181 lines) - Application orchestration
   - `application/services/plugin_executor.py` (425 lines) - Execution logic
   - `infrastructure/persistence/plugin_loader.py` (209 lines) - Repository implementation
   - Used by: Some command classes (plugin_list, plugin_info), integration tests
   - **10 active imports** across tests and new command classes

**Problems:**
- **Code Duplication**: 2,478 lines of overlapping functionality
- **Confusion**: New contributors don't know which system to use
- **Maintenance Burden**: Bug fixes must be applied to both systems
- **Architecture Violations**: Legacy system breaks Clean Architecture boundaries
- **Testing Complexity**: Need to test both implementations
- **Migration Stalled**: Started 6+ months ago, stuck at 60% complete

**Business Impact:**
- Slower development velocity (2x effort for plugin changes)
- Higher bug risk (changes can miss one system)
- Onboarding friction (2+ hours to understand dual system)
- Technical debt accumulation (estimated 2-3 weeks to fix)

## What Changes

Complete migration from legacy `core/` plugin system to Clean Architecture implementation:

### Phase 1: Preparation (Non-Breaking)
- ✅ Create comprehensive test coverage for legacy behavior
- ✅ Document all plugin manager/loader functionality
- ✅ Establish behavioral compatibility tests
- ✅ Create migration adapter for gradual transition

### Phase 2: Migration (Breaking - CLI Internal Only)
- **BREAKING**: Update all CLI command handlers to use new system
- **BREAKING**: Update main.py to initialize new architecture
- **BREAKING**: Remove core/plugin_manager.py and core/plugin_loader.py
- Preserve all user-facing CLI behavior (no breaking changes for users)
- Maintain plugin API compatibility (decorators, base classes)

### Phase 3: Cleanup
- Remove migration adapters and compatibility layers
- Update documentation to reflect new architecture
- Add architecture decision record (ADR)

### What Stays the Same (User-Facing)
- ✅ Plugin API (`@plugin_function` decorator, `BasePlugin`)
- ✅ CLI commands (`gs plugin list`, `gs <plugin> <function>`, etc.)
- ✅ Plugin.json format and metadata structure
- ✅ Shell/Config plugin execution model
- ✅ Configuration files and user settings
- ✅ Router index and shell integration

## Impact

### Affected Specifications
- **plugin-management** - NEW: Plugin lifecycle, enable/disable, health checks
- **plugin-loading** - NEW: Plugin discovery, parsing, function registration
- **plugin-execution** - NEW: Unified execution interface for all plugin types

### Affected Code

**CLI Layer** (10 files to update):
- `cli/main.py` - Replace PluginManager with PluginService
- `cli/commands.py` - Update command routing
- `cli/system_commands.py` - Update plugin commands
- `cli/command_classes/base.py` - Update base command class
- `cli/command_classes/refresh_command.py` - Update refresh logic
- `cli/command_classes/plugin_list_command.py` - Already migrated ✓
- `cli/command_classes/plugin_info_command.py` - Already migrated ✓
- `cli/command_classes/plugin_enable_command.py` - NEW: Create using new architecture
- `cli/command_classes/plugin_disable_command.py` - NEW: Create using new architecture
- `cli/command_classes/plugin_execute_command.py` - NEW: Create using new architecture

**Application Layer** (enhance existing):
- `application/services/plugin_service.py` - Add missing lifecycle methods
- `application/services/plugin_executor.py` - Add timeout enforcement, validation

**Infrastructure Layer** (enhance existing):
- `infrastructure/persistence/plugin_loader.py` - Complete implementation
- `infrastructure/persistence/plugin_repository.py` - Add query methods

**Core Layer** (DELETE):
- ❌ `core/plugin_manager.py` (568 lines) - DELETE
- ❌ `core/plugin_loader.py` (1095 lines) - DELETE

**Tests** (update 10 files):
- Update integration tests to use new system
- Update unit tests for new architecture
- Add migration compatibility tests

**Documentation** (3 files):
- Update plugin-development.md
- Update architecture.md
- Add ADR for migration decision

### Migration Risk Assessment

**High Risk:**
- Main.py initialization (affects all commands)
- Plugin loading logic (complex parsing, multiple plugin types)
- Plugin execution routing (Shell vs Python vs Config)

**Medium Risk:**
- Command handler updates (many files, but straightforward)
- Test updates (time-consuming but low complexity)

**Low Risk:**
- Documentation updates
- Cleanup of old code

### Rollback Plan

1. Keep legacy code in git history (tagged as `pre-clean-arch-migration`)
2. Create feature flag to switch between systems during rollout
3. If critical issues found:
   - Revert commits in reverse order
   - Re-enable legacy system via feature flag
   - Fix issues in new system
   - Retry migration

### Success Criteria

- ✅ All existing tests pass
- ✅ All CLI commands work identically to before
- ✅ Plugin API remains compatible
- ✅ No performance regression (< 10ms overhead)
- ✅ Zero legacy code in `core/plugin_manager.py` or `core/plugin_loader.py`
- ✅ Architecture validation passes: `ruff check src/gscripts/`
- ✅ Test coverage maintained at 80%+

### Timeline Estimate

- **Phase 1** (Preparation): 3-5 days
- **Phase 2** (Migration): 7-10 days
- **Phase 3** (Cleanup): 2-3 days

**Total**: 12-18 days (2-3 weeks)

### Dependencies

- Must complete before: Any new plugin features
- Blocks: Layer boundary violation fixes (Priority 2)
- Enables: Domain layer completion (Priority 4)
