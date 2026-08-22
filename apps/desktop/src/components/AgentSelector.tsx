import type { AgentFilter } from '../api';
import { useI18n } from '../i18n';

const options: AgentFilter[] = ['all', 'codex', 'claudeCode', 'hermes', 'openClaw', 'openCode', 'grokBuild'];

export function AgentSelector({ value, onChange }: { value: AgentFilter; onChange: (value: AgentFilter) => void }) {
  const { t } = useI18n();
  return (
    <label className="agent-filter">
      <span className="field-label">{t('scan.agent')}</span>
      <select aria-label={t('scan.agent')} value={value} onChange={(event) => onChange(event.target.value as AgentFilter)}>
        {options.map((option) => <option key={option} value={option}>{t(`agents.${option}` as Parameters<typeof t>[0])}</option>)}
      </select>
    </label>
  );
}
