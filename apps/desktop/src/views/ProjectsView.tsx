import { useEffect, useState } from 'react';
import { api, type AgentFilter, type WorkspaceDto } from '../api';
import { AgentSelector } from '../components/AgentSelector';
import { useI18n } from '../i18n';

function projectName(path: string) {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) ?? path;
}

export function ProjectsView({ onSelect, agentKind, onAgentKindChange }: { onSelect: (project: WorkspaceDto) => void; agentKind: AgentFilter; onAgentKindChange: (value: AgentFilter) => void }) {
  const [projects, setProjects] = useState<WorkspaceDto[]>([]);
  const [failed, setFailed] = useState(false);
  const { t } = useI18n();

  useEffect(() => {
    void api.workspacesList(100, 0, agentKind === 'all' ? undefined : agentKind).then(setProjects).catch(() => {
      setProjects([]);
      setFailed(true);
    });
  }, [agentKind]);

  return (
    <section className="card" aria-label="Projects">
      <div className="section-heading">
        <div><p className="eyebrow">{t('projects.workspaces')}</p><h2>{t('projects.title')}</h2></div>
        <div className="section-actions"><AgentSelector value={agentKind} onChange={onAgentKindChange} /><span className="muted">{projects.length} {projects.length === 1 ? t('projects.countOne') : t('projects.countMany')}</span></div>
      </div>
      {failed && <p className="error-message">{t('projects.failed')}</p>}
      {!failed && projects.length === 0 && (
        <p className="muted project-empty">{t('projects.empty')}</p>
      )}
      <div className="project-list">
        {projects.map((project) => (
          <button className="project-item" key={project.id} type="button" onClick={() => onSelect(project)}>
            <div className="project-heading"><strong>{projectName(project.pathNative)}</strong><span>{project.sessionCount} {t('projects.sessions')}</span></div>
            <div className="mono project-path">{project.pathNative}</div>
            {project.gitCommit && <div className="muted mono">{t('projects.git')}: {project.gitCommit}</div>}
          </button>
        ))}
      </div>
    </section>
  );
}
