import { FormEvent, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function Investigation() {
  const { hasPermission } = useAuth();
  const [params] = useSearchParams();
  const entityParam = params.get('entity') || '';
  const [cases, setCases] = useState<Record<string, unknown>[]>([]);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [newTitle, setNewTitle] = useState('');
  const [note, setNote] = useState('');

  const load = () => api.listCases().then((d) => setCases(d.cases));

  useEffect(() => {
    load();
    if (entityParam && hasPermission('cases:write')) {
      setNewTitle(`تحقيق: ${entityParam}`);
    }
  }, [entityParam, hasPermission]);

  const createCase = async (e: FormEvent) => {
    e.preventDefault();
    if (!hasPermission('cases:write')) return;
    const c = await api.createCase({ title: newTitle, description: `تحقيق في ${entityParam}`, incident_ids: [] });
    setSelected(c as Record<string, unknown>);
    load();
  };

  const openCase = async (id: string) => {
    const c = await api.getCase(id);
    setSelected(c as Record<string, unknown>);
  };

  const addNote = async () => {
    if (!selected || !note.trim()) return;
    await api.addCaseNote(String(selected.case_id), note);
    setNote('');
    openCase(String(selected.case_id));
  };

  const timeline = (selected?.timeline as Record<string, unknown>[]) || [];
  const graphNodes = [
    ...(selected?.entity_ids as string[] || []).map((e) => ({ id: e, type: 'entity', label: e })),
    ...(selected?.ip_addresses as string[] || []).map((ip) => ({ id: ip, type: 'ip', label: ip })),
  ];

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-project-diagram me-2" />مساحة عمل التحقيق في القضايا</h2>
        <p>ربط الكيانات وعناوين IP والأحداث في تحقيق موحد</p>
      </div>

      <div className="row g-3">
        <div className="col-lg-4">
          <div className="cds-card mb-3">
            <div className="cds-card-header">القضايا</div>
            <ul className="list-group list-group-flush">
              {cases.map((c) => (
                <li key={String(c.case_id)} className="list-group-item list-group-item-action" onClick={() => openCase(String(c.case_id))}>
                  {String(c.title)}
                </li>
              ))}
            </ul>
          </div>
          {hasPermission('cases:write') && (
            <form className="cds-card cds-card-body" onSubmit={createCase}>
              <input className="form-control mb-2" placeholder="عنوان القضية" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} required />
              <button type="submit" className="btn btn-primary w-100">قضية جديدة</button>
            </form>
          )}
        </div>

        <div className="col-lg-8">
          {selected ? (
            <>
              <div className="cds-card mb-3">
                <div className="cds-card-header">{String(selected.title)}</div>
                <div className="cds-card-body">
                  <p>{String(selected.description)}</p>
                  <div className="cds-graph-preview p-3 bg-dark rounded mb-3">
                    <strong className="text-white">الرسم البياني:</strong>
                    <div className="d-flex flex-wrap gap-2 mt-2">
                      {graphNodes.map((n) => (
                        <span key={n.id} className={`badge ${n.type === 'ip' ? 'bg-danger' : 'bg-info'}`}>{n.label}</span>
                      ))}
                      {graphNodes.length > 1 && graphNodes.slice(1).map((_, i) => (
                        <span key={`link-${i}`} className="text-white-50">↔</span>
                      ))}
                    </div>
                  </div>
                  <textarea className="form-control mb-2" placeholder="ملاحظة محقق..." value={note} onChange={(e) => setNote(e.target.value)} />
                  <button type="button" className="btn btn-sm btn-secondary" onClick={addNote}>إضافة ملاحظة</button>
                  <pre className="mt-3 small bg-light p-2">{String(selected.investigator_notes || '')}</pre>
                </div>
              </div>
              <div className="cds-card">
                <div className="cds-card-header">الخط الزمني</div>
                <div className="cds-timeline">
                  {timeline.map((ev, i) => (
                    <div key={i} className="cds-timeline-item p-2 border-start border-3 ms-2 mb-2">
                      <small>{new Date(Number(ev.timestamp) * 1000).toLocaleString()}</small>
                      <p className="mb-0">{String(ev.description)}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <p className="text-muted">اختر أو أنشئ قضية للبدء</p>
          )}
        </div>
      </div>
    </div>
  );
}
