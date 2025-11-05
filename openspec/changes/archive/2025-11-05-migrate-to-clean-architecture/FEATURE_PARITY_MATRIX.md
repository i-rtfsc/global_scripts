# Feature Parity Matrix: Legacy vs Clean Architecture

## PluginManager (Legacy) Public API

### Core Lifecycle Methods
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `__init__` | `(plugins_root, config_manager)` | ✅ PluginService.__init__ | Similar but uses DI |
| `initialize` | `async def()` | ✅ PluginService.initialize() | Exists |
| `load_all_plugins` | `async def()` | ✅ PluginService.load_all_plugins() | Exists |
| `reload_plugin` | `async def(plugin_name: str) -> bool` | ❌ Missing | **NEEDS IMPLEMENTATION** |

### Execution Methods
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `execute_plugin_function` | `async def(plugin_name, function_name, args) -> CommandResult` | ✅ PluginExecutor.execute() | Via PluginExecutor |

### Plugin State Management
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `enable_plugin` | `def(plugin_name: str) -> CommandResult` | ❌ Missing | **NEEDS IMPLEMENTATION** |
| `disable_plugin` | `def(plugin_name: str) -> CommandResult` | ❌ Missing | **NEEDS IMPLEMENTATION** |
| `is_plugin_enabled` | `def(plugin_name: str) -> bool` | ✅ Can check PluginMetadata | Via repository |

### Query Methods
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `list_plugins` | `def() -> Dict[str, dict]` | ✅ PluginService.get_all_plugins() | Different return format |
| `get_plugin_info` | `def(plugin_name: str) -> Optional[dict]` | ✅ PluginRepository.get_by_name() | Via repository |
| `search_functions` | `def(keyword: str) -> List[dict]` | ❌ Missing | **NEEDS IMPLEMENTATION** |

### Shell Integration
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `get_all_shortcuts` | `def() -> Dict[str, str]` | ❌ Missing | **NEEDS IMPLEMENTATION** |
| `generate_shell_functions` | `def(output_file: Path)` | ❌ Missing | In router/indexer |
| `_generate_router_index` | `def()` | ✅ router/indexer.py | Separate module |
| `_regenerate_completions` | `def()` | ❌ Missing | In setup scripts |

### Health and Monitoring
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `health_check` | `async def() -> Dict[str, Any]` | ❌ Missing | **NEEDS IMPLEMENTATION** |

### Observer Pattern
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `register_observer` | `def(observer: IPluginObserver)` | ❌ Missing | **NEEDS IMPLEMENTATION** |
| `unregister_observer` | `def(observer: IPluginObserver)` | ❌ Missing | **NEEDS IMPLEMENTATION** |
| `notify_observers` | `def(event_data: PluginEventData)` | ❌ Missing | **NEEDS IMPLEMENTATION** |

### Private/Internal Methods
| Method | Status | Notes |
|--------|--------|-------|
| `_load_plugin_states` | Internal | Can use ConfigRepository |
| `_save_plugin_states` | Internal | Can use ConfigRepository |
| `_notify` | Internal | Part of observer pattern |

---

## PluginLoader (Legacy) Public API

### Core Loading Methods
| Method | Signature | Status in New System | Notes |
|--------|-----------|---------------------|-------|
| `__init__` | `(plugins_root: Path)` | ✅ PluginRepository.__init__ | Via infrastructure |
| `load_all_plugins` | `async def() -> Dict[str, SimplePlugin]` | ✅ PluginRepository.get_all() | Exists |
| `load_plugin` | `async def(plugin_name, is_example, is_custom, plugin_dir) -> Optional[SimplePlugin]` | ✅ PluginRepository.get_by_name() | Exists |

### Function Discovery (Internal - used by loader)
| Method | Purpose | Status in New System |
|--------|---------|---------------------|
| `_discover_functions` | Discover all function types | ✅ In infrastructure/persistence/plugin_loader.py |
| `_discover_python_functions` | Python @plugin_function | ✅ In parsers/python_parser.py |
| `_discover_script_functions` | Shell annotations | ✅ In parsers/shell_parser.py |
| `_discover_config_functions` | JSON commands | ✅ In parsers/config_parser.py |
| `_discover_subplugin_functions` | Hybrid plugins | ✅ Handled recursively |

### Shell Generation
| Method | Purpose | Status in New System |
|--------|---------|---------------------|
| `generate_shell_functions` | Generate shell wrappers | ❌ In router/indexer (separate) |
| `get_plugin_shortcuts` | Get shortcut commands | ❌ Missing |
| `_generate_env_functions` | Generate env setup | ❌ In setup scripts |
| `_generate_completion_functions` | Generate completions | ❌ In shell_completion/ |

---

## Feature Parity Summary

### ✅ Implemented in New System (12/24)
1. Basic initialization and loading
2. Plugin execution via PluginExecutor
3. Plugin querying via Repository
4. Function discovery via parsers
5. Plugin metadata handling
6. Async loading

### ❌ Missing in New System (12/24) - **CRITICAL FOR PHASE 1**
1. **Plugin state management**: `enable_plugin()`, `disable_plugin()`
2. **Observer pattern**: `register_observer()`, `unregister_observer()`, `notify_observers()`
3. **Health check**: `health_check()`
4. **Function search**: `search_functions()`
5. **Shortcuts**: `get_all_shortcuts()`, `get_plugin_shortcuts()`
6. **Plugin reload**: `reload_plugin()`
7. **Shell generation**: Some methods moved to other modules

### 📝 Moved to Other Modules (not missing, just relocated)
1. Shell function generation → `router/indexer.py`
2. Completion generation → `shell_completion/`
3. Environment setup → `scripts/setup.py`

---

## Phase 1 Implementation Priorities

### High Priority (Blocking Migration)
1. ✅ **enable_plugin()** - Required for `gs plugin enable`
2. ✅ **disable_plugin()** - Required for `gs plugin disable`
3. ✅ **health_check()** - Required for `gs doctor`
4. ✅ **Observer pattern** - Used for logging/monitoring
5. ✅ **get_enabled_plugins()** - Used by CLI commands
6. ✅ **get_plugins_by_type()** - Used by plugin listing

### Medium Priority (Nice to Have)
1. ⚠️ **search_functions()** - Used but can defer
2. ⚠️ **reload_plugin()** - Development feature, can defer
3. ⚠️ **get_all_shortcuts()** - Used by shell integration

### Low Priority (Can Defer to Phase 2/3)
1. ⏸️ Shell generation methods - Already in other modules
2. ⏸️ Completion generation - Already in other modules
3. ⏸️ Environment setup - Already in scripts

---

## Interface Compatibility Notes

### Return Type Differences
- **Legacy**: Returns `Dict[str, dict]` for plugin lists
- **New**: Returns `List[PluginMetadata]`
- **Solution**: Adapter will translate between formats

### Async/Sync Differences
- **Legacy**: Mix of sync (enable/disable) and async (load/execute)
- **New**: All methods async
- **Solution**: Adapter will provide sync wrappers where needed

### Error Handling Differences
- **Legacy**: Returns `CommandResult` with success/error
- **New**: Returns `CommandResult` (same pattern)
- **Solution**: No translation needed

---

## Implementation Checklist for Phase 1

### Task 3: Feature Parity Implementation
- [ ] 3.2 Add `enable_plugin()` to PluginService
- [ ] 3.3 Add `disable_plugin()` to PluginService
- [ ] 3.4 Add `health_check()` to PluginService
- [ ] 3.5 Implement `IPluginObserver` in domain/interfaces/
- [ ] 3.6 Add observer methods to PluginService
- [ ] 3.7 Add `get_enabled_plugins()` to PluginService
- [ ] 3.8 Add `get_plugins_by_type()` to PluginService
- [ ] 3.9 Add `get_plugin_by_name()` to PluginService

### Task 4: PluginExecutor Enhancements
- [ ] 4.1 Add command validation (whitelist/blacklist)
- [ ] 4.2 Add timeout enforcement
- [ ] 4.3 Add argument sanitization
- [ ] 4.4 Add subprocess cleanup on timeout

### Task 5: PluginRepository Enhancements
- [ ] 5.1 Add `get_enabled()` method
- [ ] 5.2 Add `get_by_type()` method
- [ ] 5.3 Add `update_enabled_status()` method
