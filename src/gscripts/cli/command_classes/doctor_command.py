"""
DoctorCommand - 系统诊断命令
检查环境配置和补全状态
"""

from typing import List
from pathlib import Path

from .base import SimpleCommand
from ...core.config_manager import CommandResult


class DoctorCommand(SimpleCommand):
    """系统诊断命令 - 检查环境和补全"""

    @property
    def name(self) -> str:
        return "doctor"

    @property
    def aliases(self) -> List[str]:
        return []

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.doctor_help")

    def _execute(self, args: List[str]) -> CommandResult:
        """执行诊断"""
        try:
            env_path = Path(__file__).resolve().parents[3] / 'env.sh'
            comp_dir = self.constants.get_config_dir() / 'completions'

            zsh_ok = False
            bash_ok = False
            hints: List[str] = []

            if env_path.exists():
                with open(env_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                zsh_ok = 'compinit' in content or 'compdef' in content
                bash_ok = 'complete -F' in content or 'bash_completion' in content

            if not (comp_dir.exists() and any(comp_dir.glob('gs.*'))):
                hints.append(self.i18n.get_message('commands.loading_error'))

            details = {
                'env.sh': 'present' if env_path.exists() else 'missing',
                'completions_dir': str(comp_dir),
                'zsh_completion_bits': 'ok' if zsh_ok else 'missing',
                'bash_completion_bits': 'ok' if bash_ok else 'missing'
            }

            if hints:
                details['hints'] = ', '.join(hints)

            table = self.formatter.format_info_table(details)

            return CommandResult(
                success=True,
                message=self.i18n.get_message('commands.doctor'),
                output=table
            )

        except Exception as e:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.execution_failed'),
                exit_code=self.constants.EXIT_EXECUTION_ERROR
            )
