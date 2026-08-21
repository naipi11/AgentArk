import { useEffect, useState } from 'react';
import { api, type WorkspaceDto } from '../api';

function projectName(path: string) {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) ?? path;
}

export function ProjectsView() {
  const [projects, setProjects] = useState<WorkspaceDto[]>([]);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    void api.workspacesList().then(setProjects).catch(() => {
      setProjects([]);
      setFailed(true);
    });
  }, []);

  return (
    <section className="card" aria-label="Projects">
      <div className="section-heading">
        <div><p className="eyebrow">Workspaces</p><h2>Projects</h2></div>
        <span className="muted">{projects.length} project{projects.length === 1 ? '' : 's'}</span>
      </div>
      {failed && <p className="error-message">无法读取项目索引，请重新打开客户端。</p>}
      {!failed && projects.length === 0 && (
        <p className="muted project-empty">尚未建立项目归属。请在 Scan 页面重新扫描一次 Codex 数据。</p>
      )}
      <div className="project-list">
        {projects.map((project) => (
          <article className="project-item" key={project.id}>
            <div className="project-heading"><strong>{projectName(project.pathNative)}</strong><span>{project.sessionCount} sessions</span></div>
            <div className="mono project-path">{project.pathNative}</div>
            {project.gitCommit && <div className="muted mono">Git: {project.gitCommit}</div>}
          </article>
        ))}
      </div>
    </section>
  );
}
