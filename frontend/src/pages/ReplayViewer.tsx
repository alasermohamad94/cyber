import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { severityBadgeClass } from '../utils/cds';

export default function ReplayViewer() {
  const [params] = useSearchParams();
  const entityId = params.get('entity') || '';
  const [entity, setEntity] = useState(entityId);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [index, setIndex] = useState(0);
  const [data, setData] = useState<Record<string, unknown> | null>(null);

  const load = () => {
    if (!entity.trim()) return;
    api.replayForensics({ entity_id: entity }).then(setData).catch(console.error);
    setIndex(0);
  };

  useEffect(() => {
    if (entityId) load();
  }, [entityId]);

  useEffect(() => {
    if (!playing || !data?.events) return;
    const events = data.events as Record<string, unknown>[];
    if (index >= events.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setIndex((i) => i + 1), 1000 / speed);
    return () => clearTimeout(timer);
  }, [playing, index, speed, data]);

  const events = (data?.events as Record<string, unknown>[]) || [];
  const visible = events.slice(0, index + 1);

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-history me-2" />مستعرض إعادة تمثيل الأحداث</h2>
        <p>تحليل جنائي — خط زمني تفاعلي مع عناصر تحكم التشغيل</p>
      </div>

      <div className="cds-card mb-3">
        <div className="cds-card-body d-flex flex-wrap gap-2 align-items-end">
          <div>
            <label className="form-label">معرف الكيان</label>
            <input className="form-control" value={entity} onChange={(e) => setEntity(e.target.value)} />
          </div>
          <button type="button" className="btn btn-primary" onClick={load}>تحميل</button>
          <button type="button" className="btn btn-success" onClick={() => setPlaying(true)} disabled={!events.length}>
            <i className="fas fa-play" />
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => setPlaying(false)}>
            <i className="fas fa-pause" />
          </button>
          <select className="form-select w-auto" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            <option value={0.5}>0.5×</option>
            <option value={1}>1×</option>
            <option value={2}>2×</option>
            <option value={4}>4×</option>
          </select>
          <input type="range" min={0} max={Math.max(0, events.length - 1)} value={index} onChange={(e) => setIndex(Number(e.target.value))} className="flex-grow-1" />
        </div>
      </div>

      <div className="row g-3">
        <div className="col-lg-8">
          <div className="cds-card">
            <div className="cds-card-header">تسلسل الأحداث ({visible.length}/{events.length})</div>
            <div style={{ maxHeight: 400, overflow: 'auto' }}>
              {visible.map((ev, i) => (
                <div key={i} className={`p-2 border-bottom ${i === index ? 'bg-light' : ''}`}>
                  <span className={severityBadgeClass(String(ev.severity))}>{String(ev.severity)}</span>
                  <span className="ms-2">{new Date(Number(ev.timestamp) * 1000).toLocaleString()}</span>
                  <p className="mb-0 mt-1">{String(ev.description)}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="col-lg-4">
          <div className="cds-card">
            <div className="cds-card-header">مؤشرات الثقة</div>
            <div className="cds-card-body">
              {(data?.trust_snapshots as Record<string, unknown>[] || []).map((t, i) => (
                <p key={i}>
                  الثقة: {Number(t.trust_score).toFixed(0)} | المخاطر: {Number(t.risk_score).toFixed(0)} ({String(t.risk_level)})
                </p>
              ))}
              {!data && <p className="text-muted">حمّل كياناً لعرض البيانات</p>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
