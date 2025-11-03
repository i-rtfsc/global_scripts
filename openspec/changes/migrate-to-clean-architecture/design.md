# Design Document: Clean Architecture Migration

## Context

Global Scripts V5 began migrating to Clean Architecture approximately 6 months ago to improve:
- Testability (dependency injection, mocked infrastructure)
- Maintainability (clear layer boundaries, separation of concerns)
- Extensibility (plugin system based on interfaces)

**Current State**: Migration is 60% complete:
- ✅ Infrastructure layer implemented (repositories, persistence, execution)
- ✅ Application layer partially implemented (PluginService, PluginExecutor)
- ✅ Domain interfaces defined (IPluginRepository, IConfigRepository)
- ✅ DI container configured
- ✅ Some command classes migrated (plugin_list, plugin_info)
- ❌ CLI entry point still uses legacy system
- ❌ Most command handlers still use legacy system
- ❌ Legacy code not removed

**Stakeholders:**
- Developers: Need single, clear plugin system
- Users: Expect zero breaking changes to CLI/plugin API
- Contributors: Need simple onboarding without dual-system confusion

**Constraints:**
- Must maintain backward compatibility for users
- Must preserve all existing plugin functionality
- Must not break plugin API (`@plugin_function`, `BasePlugin`)
- Must complete in 2-3 weeks (business priority)

## Goals / Non-Goals

### Goals
1. **Single Plugin System**: One implementation in Clean Architecture layers
2. **Zero User Impact**: All CLI commands work identically
3. **Improved Testability**: All components injectable and testable
4. **Clear Boundaries**: Strict layer separation (CLI → Application → Domain ← Infrastructure)
5. **Complete Migration**: Remove all legacy `core/` plugin code

### Non-Goals
1. **Plugin API Changes**: Not changing `@plugin_function` decorator or `BasePlugin`
2. **New Features**: Not adding new plugin capabilities (focus on migration)
3. **Performance Optimization**: Not changing execution model (keep existing performance)
4. **User Config Changes**: Not changing gs.json format or configuration
5. **Domain Layer Completion**: Not implementing rich domain entities (Priority 4 task)

## Decisions

### Decision 1: Complete Migration to Clean Architecture (Not Rollback)

**Options Considered:**
1. **Complete migration to Clean Architecture** ← CHOSEN
2. Rollback new system, keep only legacy
3. Keep both systems permanently (feature flag switching)

**Rationale:**
- **Chosen Option 1** because:
  - New architecture is better designed (testability, maintainability)
  - 60% already complete (sunk cost)
  - Rollback loses DI benefits, testing improvements
  - Keeping both systems is unsustainable (2x maintenance)

**Trade-offs:**
- ✅ Better long-term architecture
- ✅ Easier to extend with new features
- ✅ Better test coverage
- ❌ Short-term migration effort (2-3 weeks)
- ❌ Risk of regressions during migration

**Alternatives Rejected:**
- **Option 2 (Rollback)**: Loses all benefits of Clean Architecture, wastes 6 months of work
- **Option 3 (Keep Both)**: Unsustainable, doubles maintenance burden, confuses contributors

### Decision 2: Phased Migration with Feature Flag Safety

**Approach:**
1. **Phase 1**: Add comprehensive tests for legacy behavior
2. **Phase 2**: Migrate CLI to new system (feature flag to switch back)
3. **Phase 3**: Remove legacy code after validation

**Rationale:**
- Gradual migration reduces risk
- Feature flag enables quick rollback if issues found
- Tests ensure behavioral equivalence

**Implementation:**
```python
# cli/main.py
USE_CLEAN_ARCHITECTURE = os.getenv('GS_USE_CLEAN_ARCH', 'true') == 'true'

if USE_CLEAN_ARCHITECTURE:
    from gscripts.application.services import PluginService
    self.plugin_manager = PluginService(...)  # New
else:
    from gscripts.core.plugin_manager import PluginManager
    self.plugin_manager = PluginManager(...)  # Legacy
```

### Decision 3: Adapter Pattern for Gradual Migration

**Pattern:**
Create `PluginManagerAdapter` that wraps new `PluginService` with legacy interface.

**Benefits:**
- CLI code can migrate gradually (file by file)
- Both systems can coexist temporarily
- Adapter deleted in Phase 3

**Example:**
```python
class PluginManagerAdapter:
    """Adapter to make PluginService compatible with legacy PluginManager interface"""

    def __init__(self, plugin_service: PluginService):
        self._service = plugin_service

    async def load_plugins(self):
        """Legacy method → delegate to new service"""
        return await self._service.load_all_plugins()

    async def execute_plugin_function(self, plugin_name, function_name, args):
        """Legacy method → delegate to new executor"""
        return await self._service.execute_function(plugin_name, function_name, args)
```

### Decision 4: Test-First Migration Strategy

**Strategy:**
1. Create behavioral compatibility tests before changing code
2. Tests run against both legacy and new systems
3. Migration is complete when all tests pass with new system
4. Legacy code removed only after tests pass

**Benefits:**
- High confidence in behavioral equivalence
- Regressions caught immediately
- Clear success criteria

### Decision 5: Preserve Plugin Loader Parser Logic

**Decision:** Keep complex parsing logic from legacy `plugin_loader.py`, refactor into new architecture.

**Rationale:**
- Plugin parsing (decorators, annotations, JSON) is complex and battle-tested
- Rewriting risks introducing bugs
- Focus on architectural migration, not feature changes

**Approach:**
- Extract parsing logic into infrastructure layer
- Improve modularity (separate Python/Shell/Config parsers)
- Add unit tests for each parser
- Maintain identical parsing behavior

## Risks / Trade-offs

### Risk 1: Regression in Plugin Loading
**Likelihood**: Medium | **Impact**: High

**Description**: Complex plugin discovery logic (decorators, annotations, subplugins) may break during migration.

**Mitigation:**
- ✅ Create comprehensive plugin loading tests before migration
- ✅ Test all plugin types (Python, Shell, Config, Hybrid)
- ✅ Test edge cases (missing metadata, invalid syntax, circular dependencies)
- ✅ Keep legacy parser logic intact, just reorganize

**Rollback:** Feature flag can switch back to legacy loader instantly

### Risk 2: Performance Regression
**Likelihood**: Low | **Impact**: Medium

**Description**: New architecture might add overhead (DI resolution, extra abstraction layers).

**Mitigation:**
- ✅ Benchmark plugin loading time before/after
- ✅ Benchmark command execution overhead
- ✅ Optimize DI container (singleton instances, lazy loading)
- ✅ Success criterion: < 10ms overhead

**Rollback:** Revert if performance degrades > 10%

### Risk 3: Incomplete Functionality
**Likelihood**: Medium | **Impact**: High

**Description**: Legacy system may have features not yet in new system (observer pattern, health checks, plugin state management).

**Mitigation:**
- ✅ Audit all legacy methods and ensure equivalents exist
- ✅ Feature parity checklist in tasks.md
- ✅ Integration tests cover all CLI commands

**Rollback:** Delay migration until feature parity achieved

### Risk 4: Breaking Changes for Plugin Authors
**Likelihood**: Low | **Impact**: Critical

**Description**: Plugin API changes would break all existing plugins.

**Mitigation:**
- ✅ NO changes to `@plugin_function` decorator
- ✅ NO changes to `BasePlugin` interface
- ✅ NO changes to plugin.json format
- ✅ Test with existing plugins (android, multirepo, dotfiles)

**Rollback:** If any plugin API changes detected, revert immediately

### Trade-off 1: Short-term Effort vs Long-term Maintainability

**Trade-off:**
- **Cost**: 2-3 weeks of migration effort, potential bugs
- **Benefit**: Sustainable architecture, easier future development

**Decision:** Accept short-term cost for long-term benefits

### Trade-off 2: Feature Freeze vs Parallel Development

**Trade-off:**
- **Option A**: Freeze plugin features during migration (safer)
- **Option B**: Allow parallel feature development (faster)

**Decision:** **Option A** - Feature freeze on plugin system during migration to reduce merge conflicts and testing complexity.

## Migration Plan

### Step 1: Audit and Document (Phase 1, Day 1-2)
1. ✅ Document all PluginManager methods and their usage
2. ✅ Document all PluginLoader methods and their usage
3. ✅ Create feature parity matrix (legacy vs new)
4. ✅ Identify missing features in new system

### Step 2: Achieve Feature Parity (Phase 1, Day 3-5)
1. ✅ Add missing methods to PluginService (enable, disable, health_check, observer)
2. ✅ Add missing methods to PluginExecutor (validation, timeout, whitelist/blacklist)
3. ✅ Complete PluginRepository implementation (get_enabled, get_by_type)
4. ✅ Create comprehensive test suite for new system

### Step 3: Create Migration Adapter (Phase 1, Day 5)
1. ✅ Implement PluginManagerAdapter wrapper
2. ✅ Test adapter against legacy test suite
3. ✅ Validate behavioral equivalence

### Step 4: Migrate CLI Entry Point (Phase 2, Day 6-7)
1. ✅ Update main.py to use PluginService via adapter
2. ✅ Add feature flag (`GS_USE_CLEAN_ARCH`)
3. ✅ Test all CLI commands with new system
4. ✅ Monitor for regressions

### Step 5: Migrate Command Handlers (Phase 2, Day 8-12)
1. ✅ Migrate system_commands.py
2. ✅ Migrate command_classes/base.py
3. ✅ Migrate command_classes/refresh_command.py
4. ✅ Create new command classes (enable, disable, execute)
5. ✅ Test each command after migration

### Step 6: Remove Legacy Code (Phase 3, Day 13-14)
1. ✅ Remove feature flag (default to new system)
2. ✅ Delete core/plugin_manager.py
3. ✅ Delete core/plugin_loader.py
4. ✅ Remove migration adapter
5. ✅ Update all imports

### Step 7: Documentation and Cleanup (Phase 3, Day 15-18)
1. ✅ Update plugin-development.md
2. ✅ Update architecture.md
3. ✅ Add ADR (Architecture Decision Record)
4. ✅ Run full test suite
5. ✅ Code review and refinement

## Validation Strategy

### Automated Tests
```bash
# Phase 1: Both systems pass same tests
pytest tests/ -v --both-systems

# Phase 2: New system passes all tests
pytest tests/ -v --new-system-only

# Phase 3: Legacy code removed
pytest tests/ -v  # Only new system exists
```

### Manual Validation
1. Test all CLI commands manually:
   ```bash
   gs help
   gs version
   gs plugin list
   gs plugin info android
   gs plugin enable dotfiles
   gs plugin disable grep
   gs android adb devices
   gs multirepo sync mini-aosp
   ```

2. Test all plugin types:
   - Python plugin (android, multirepo)
   - Shell plugin (grep)
   - Config plugin (navigator)
   - Hybrid plugin (system)

3. Performance benchmarks:
   ```bash
   time gs plugin list  # Should be < 500ms
   time gs android adb devices  # Should be < 100ms overhead
   ```

### Rollback Triggers

Automatically rollback if:
- ❌ Any integration test fails
- ❌ Performance degrades > 10%
- ❌ Any CLI command behaves differently
- ❌ Plugin API compatibility breaks

Manual rollback if:
- ❌ Critical bug discovered in production
- ❌ User reports breaking changes
- ❌ Migration timeline exceeds 3 weeks

## Open Questions

### Q1: Should we create domain entities or keep anemic models?

**Context**: Current migration uses anemic `PluginMetadata` dataclass. Clean Architecture recommends rich domain entities.

**Options:**
1. Keep anemic models (current approach)
2. Create rich domain entities with behavior

**Recommendation**: **Option 1** for this migration, defer to Priority 4 task. Rationale:
- Reduces scope of this migration
- Domain entities require more design work
- Can be done incrementally later

### Q2: Should we migrate router indexer at same time?

**Context**: Router indexer (`router/indexer.py`) also uses legacy plugin loader.

**Options:**
1. Migrate router indexer in this change
2. Defer to separate change

**Recommendation**: **Option 1** - Include router indexer migration because:
- Router depends on plugin loading
- Delaying creates dependency issues
- Small additional scope (~200 lines)

### Q3: Should we preserve observer pattern?

**Context**: Legacy PluginManager has observer pattern for lifecycle events. New system doesn't have it yet.

**Decision**: **Yes**, implement observer pattern in PluginService because:
- Used by logging and monitoring
- Part of existing behavior
- Required for feature parity

**Implementation**: Add `IPluginObserver` interface in domain, implement in PluginService.
