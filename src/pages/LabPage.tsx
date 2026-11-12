import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { ExternalLink, Tag } from '../components/data';
import { Icon } from '../components/Icon';
import { ConfirmDialog } from '../components/Modal';
import { Button, PageHeader, Panel } from '../components/ui';
import type { MessageKey } from '../i18n';
import { CATALOG, loadScenario } from '../lab/catalog';
import { bestAnswer, buildLabReport, scoreAttempt, scoreStep } from '../lab/engine';
import type { Scenario, Step } from '../lab/model';
import { clearProgress, emptyProgress, loadAllProgress, loadProgress, saveProgress, type Progress } from '../lab/progress';
import { downloadText, fileStamp } from '../lib/export';
import NotFoundPage from './NotFoundPage';

// ── Index ───────────────────────────────────────────────────────────────────

export function LabIndexPage() {
  const { t, language } = useI18n();
  const [progress, setProgress] = useState<Record<string, Progress>>({});

  useEffect(() => {
    let cancelled = false;
    loadAllProgress().then(
      (all) => !cancelled && setProgress(all),
      () => undefined,
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <PageHeader title={t('nav.lab')} intro={t('lab.intro')} />
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {CATALOG.map((scenario) => {
          const attempt = progress[scenario.id];
          const status = !attempt
            ? t('lab.status.new')
            : attempt.score
              ? attempt.scenarioVersion === scenario.version
                ? t('lab.status.done', { total: attempt.score.total, max: attempt.score.max })
                : t('lab.status.outdated')
              : t('lab.status.inProgress', { done: Object.keys(attempt.answers).length });
          return (
            <li key={scenario.id}>
              <Link to={`/lab/${scenario.id}`} className="block h-full rounded-sm border border-line bg-surface p-4 hover:border-line-strong">
                <span className="block font-medium text-fg">{scenario.title[language]}</span>
                <span className="mt-2 flex flex-wrap items-center gap-2 text-xs text-subtle">
                  <Tag tone={scenario.difficulty === 'advanced' ? 'alert' : scenario.difficulty === 'intermediate' ? 'gold' : 'neutral'}>{t(`lab.difficulty.${scenario.difficulty}` as MessageKey)}</Tag>
                  {t('lab.minutes', { n: scenario.minutes })}
                  <span className="font-mono">{scenario.techniques.join(' · ')}</span>
                </span>
                <span className={`mt-2 block text-xs ${attempt?.score ? 'text-gold' : 'text-muted'}`}>{status}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </>
  );
}

// ── Scenario ────────────────────────────────────────────────────────────────

function StepView({ step, index, total, answer, onSubmit, scenario }: { step: Step; index: number; total: number; answer: string[] | undefined; onSubmit: (selected: string[]) => void; scenario: Scenario }) {
  const { t, language } = useI18n();
  const [selected, setSelected] = useState<string[]>([]);
  const locked = answer !== undefined;
  const chosen = answer ?? selected;
  const best = bestAnswer(step);
  const evidenceTitles = step.evidence.map((id) => scenario.evidence.find((item) => item.id === id)?.title[language]).filter(Boolean).join(', ');
  const toggle = (id: string) => {
    if (locked) return;
    setSelected(step.mode === 'single' ? [id] : selected.includes(id) ? selected.filter((value) => value !== id) : [...selected, id]);
  };
  return (
    <section aria-labelledby={`step-${step.id}`} className="rounded-sm border border-line bg-surface p-4">
      <p className="text-xs uppercase tracking-wider text-subtle">
        {t('lab.step', { n: index + 1, total })} · {t(`lab.kind.${step.kind}` as MessageKey)}
      </p>
      <h2 id={`step-${step.id}`} className="mt-1 text-base font-medium text-fg">{step.prompt[language]}</h2>
      <p className="mt-1 text-xs text-muted">{t(step.mode === 'single' ? 'lab.single' : 'lab.multiple')}{evidenceTitles ? ` ${t('lab.lookAt', { items: evidenceTitles })}` : ''}</p>
      <fieldset className="mt-3 space-y-2" disabled={locked}>
        <legend className="sr-only">{step.prompt[language]}</legend>
        {step.options.map((option) => {
          const isChosen = chosen.includes(option.id);
          const isBest = best.includes(option.id);
          return (
            <div key={option.id} className={`rounded-sm border p-2.5 text-sm ${locked ? (isBest ? 'border-gold/60' : isChosen ? 'border-accent/60' : 'border-line') : 'border-line'}`}>
              <label className="flex cursor-pointer items-start gap-2">
                <input type={step.mode === 'single' ? 'radio' : 'checkbox'} name={`step-${step.id}`} checked={isChosen} onChange={() => toggle(option.id)} className="mt-1" />
                <span className="text-fg">{option.text[language]}</span>
              </label>
              {locked && (isChosen || isBest) ? (
                <p className="mt-1.5 pl-6 text-xs text-muted">
                  {isChosen ? <Tag tone={isBest ? 'gold' : 'alert'}>{t('lab.selected')}</Tag> : null} {isBest && !isChosen ? <Tag tone="gold">{t('lab.expected')}</Tag> : null} {option.feedback[language]}
                </p>
              ) : null}
            </div>
          );
        })}
      </fieldset>
      {locked ? (
        <div className="mt-3 space-y-1 text-sm">
          <p className="font-medium text-gold">{t('lab.points', { points: scoreStep(step, chosen), max: step.points })}</p>
          <p className="text-xs text-subtle">{t('lab.locked')}</p>
          <p className="text-xs text-subtle">
            {t('lab.references')}:{' '}
            {step.references.map((reference, position) => (
              <span key={reference.label}>
                {position > 0 ? ' · ' : ''}
                <ExternalLink href={reference.url}>{reference.label}</ExternalLink>
              </span>
            ))}
          </p>
        </div>
      ) : (
        <Button variant="danger" className="mt-3" disabled={selected.length === 0} onClick={() => onSubmit(selected)}>
          {t('lab.submit')}
        </Button>
      )}
    </section>
  );
}

export function LabScenarioPage() {
  const { t, language } = useI18n();
  const { scenarioId = '' } = useParams();
  const known = CATALOG.some((entry) => entry.id === scenarioId);
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [persistent, setPersistent] = useState(true);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    if (!known) return;
    let cancelled = false;
    void (async () => {
      const loaded = await loadScenario(scenarioId);
      let stored: Progress | null = null;
      try {
        stored = await loadProgress(scenarioId);
      } catch {
        if (!cancelled) setPersistent(false);
      }
      if (cancelled || !loaded) return;
      setScenario(loaded);
      setProgress(stored ?? emptyProgress(loaded.version));
    })();
    return () => {
      cancelled = true;
    };
  }, [scenarioId, known]);

  const outdated = scenario !== null && progress !== null && progress.scenarioVersion !== scenario.version;
  const score = useMemo(() => (scenario && progress && !outdated ? scoreAttempt(scenario, progress.answers) : null), [scenario, progress, outdated]);

  if (!known) return <NotFoundPage />;
  if (!scenario || !progress) return <p className="text-sm text-muted">{t('app.loading')}</p>;

  const persist = (next: Progress) => {
    setProgress(next);
    void saveProgress(scenario.id, next).then((saved) => {
      if (!saved) setPersistent(false);
    });
  };

  const submit = (step: Step, selected: string[]) => {
    if (progress.answers[step.id]) return;
    const answers = { ...progress.answers, [step.id]: selected };
    const done = scenario.steps.every((candidate) => answers[candidate.id]);
    const result = scoreAttempt(scenario, answers);
    persist({ ...progress, answers, completedAt: done ? new Date().toISOString() : null, score: done ? { total: result.total, max: result.max } : null });
  };

  const answeredCount = scenario.steps.filter((step) => progress.answers[step.id]).length;
  const visibleSteps = outdated ? [] : scenario.steps.slice(0, Math.min(answeredCount + 1, scenario.steps.length));
  const complete = !outdated && answeredCount === scenario.steps.length;

  const download = () => {
    const report = buildLabReport(scenario, progress.answers, language, {
      kind: (kind) => t(`lab.kind.${kind}` as MessageKey),
      yourAnswer: t('lab.selected'),
      bestAnswer: t('lab.expected'),
      score: t('lab.scoreLabel'),
      context: t('lab.context'),
      debrief: t('lab.debrief'),
      lessons: t('lab.lessons'),
      references: t('lab.references'),
      syntheticNote: t('lab.reportSynthetic'),
    }, progress.completedAt ?? '');
    downloadText(`blackwatch-lab-${scenario.id}-${fileStamp()}.md`, report, 'text/markdown;charset=utf-8');
  };

  return (
    <>
      <Link to="/lab" className="mb-4 inline-flex items-center gap-2 text-sm text-muted hover:text-fg">
        <Icon name="arrow" className="rotate-180" />
        {t('lab.back')}
      </Link>
      <PageHeader
        title={scenario.title[language]}
        aside={
          <div className="flex flex-wrap items-center gap-2">
            <Tag>{t(`lab.difficulty.${scenario.difficulty}` as MessageKey)}</Tag>
            {scenario.techniques.map((technique) => (
              <Link key={technique} to={`/attack/${technique}`} className="font-mono text-xs text-accent hover:underline">{technique}</Link>
            ))}
          </div>
        }
      />
      {!persistent ? <p className="mb-4 text-sm text-gold">{t('lab.storage')}</p> : null}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title={t('lab.context')}>
            <p className="text-sm text-fg">{scenario.context[language]}</p>
            <h3 className="mt-3 text-xs font-semibold uppercase tracking-wider text-subtle">{t('lab.incident')}</h3>
            <p className="mt-1 text-sm text-fg">{scenario.incident[language]}</p>
          </Panel>
          <Panel title={t('lab.evidence')}>
            <div className="space-y-2">
              {scenario.evidence.map((item, index) => (
                <details key={item.id} open={index === 0} className="rounded-sm border border-line">
                  <summary className="cursor-pointer px-3 py-2 text-sm text-fg">
                    {item.title[language]} <span className="text-xs text-subtle">· {t('lab.evidenceSynthetic')}</span>
                  </summary>
                  <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all border-t border-line bg-bg p-2.5 font-mono text-xs text-muted">{item.content}</pre>
                </details>
              ))}
            </div>
          </Panel>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          {outdated && progress.score ? (
            <p className="rounded-sm border border-line-strong bg-surface p-3 text-sm text-gold">
              {t('lab.outdated', { old: progress.scenarioVersion, current: scenario.version, total: progress.score.total, max: progress.score.max })}
            </p>
          ) : null}
          {visibleSteps.map((step, index) => (
            <StepView key={`${progress.startedAt}-${step.id}`} step={step} index={index} total={scenario.steps.length} answer={progress.answers[step.id]} onSubmit={(selected) => submit(step, selected)} scenario={scenario} />
          ))}
          {complete && score ? (
            <Panel title={t('lab.complete')}>
              <p className="text-lg font-semibold text-gold">{t('lab.score', { total: score.total, max: score.max })}</p>
              <h3 className="mt-3 text-xs font-semibold uppercase tracking-wider text-subtle">{t('lab.debrief')}</h3>
              <p className="mt-1 text-sm text-fg">{scenario.debrief[language]}</p>
              <h3 className="mt-3 text-xs font-semibold uppercase tracking-wider text-subtle">{t('lab.lessons')}</h3>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted">
                {scenario.lessons.map((lesson) => <li key={lesson.en}>{lesson[language]}</li>)}
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button onClick={download}>{t('lab.download')}</Button>
              </div>
            </Panel>
          ) : null}
          {answeredCount > 0 || outdated ? (
            <div>
              <Button variant="ghost" onClick={() => setConfirming(true)}>{t('lab.restart')}</Button>
            </div>
          ) : null}
        </div>
      </div>
      <ConfirmDialog
        open={confirming}
        title={t('lab.restartTitle')}
        body={t('lab.restartBody')}
        confirmLabel={t('lab.restart')}
        onCancel={() => setConfirming(false)}
        onConfirm={() => {
          setConfirming(false);
          void clearProgress(scenario.id).catch(() => setPersistent(false));
          setProgress(emptyProgress(scenario.version));
        }}
      />
    </>
  );
}
