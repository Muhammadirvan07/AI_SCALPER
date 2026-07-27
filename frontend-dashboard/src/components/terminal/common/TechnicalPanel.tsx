import { ChevronDown, Maximize2, Minimize2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import type { TerminalPanelState } from '../../../types/terminal'
import { DataStateBoundary } from './DataStateBoundary'

interface TechnicalPanelProps {
  code: string
  title: string
  subtitle?: string
  state?: TerminalPanelState
  onRetry?: () => void
  preserveContent?: boolean
  action?: ReactNode
  children: ReactNode
  className?: string
  summary?: string
  collapsible?: boolean
}

export function TechnicalPanel({
  code,
  title,
  subtitle,
  state = 'connected',
  onRetry,
  preserveContent = false,
  action,
  children,
  className = '',
  summary,
  collapsible = true,
}: TechnicalPanelProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const contentId = `panel-${code.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`

  return (
    <section
      className={`qt-panel ${expanded ? 'qt-panel--expanded' : ''} ${className}`}
      aria-labelledby={`${contentId}-title`}
    >
      <header className="qt-panel__header">
        <div className="qt-panel__identity">
          <span className="qt-panel__code">{code}</span>
          <div>
            <h2 id={`${contentId}-title`} className="qt-panel__title">
              {title}
            </h2>
            {subtitle ? <p className="qt-panel__subtitle">{subtitle}</p> : null}
          </div>
        </div>
        <div className="qt-panel__actions">
          {action}
          <button
            type="button"
            className="qt-icon-button qt-panel__expand"
            aria-label={expanded ? `Pulihkan ${title}` : `Perbesar ${title}`}
            aria-pressed={expanded}
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? (
              <Minimize2 aria-hidden="true" className="size-3.5" />
            ) : (
              <Maximize2 aria-hidden="true" className="size-3.5" />
            )}
          </button>
          {collapsible ? (
            <button
              type="button"
              className="qt-icon-button qt-panel__collapse"
              aria-label={collapsed ? `Buka ${title}` : `Ciutkan ${title}`}
              aria-expanded={!collapsed}
              aria-controls={contentId}
              onClick={() => setCollapsed((value) => !value)}
            >
              <ChevronDown
                aria-hidden="true"
                className={`size-4 transition-transform ${collapsed ? '-rotate-90' : ''}`}
              />
            </button>
          ) : null}
        </div>
      </header>
      <div id={contentId} className="qt-panel__content" hidden={collapsed}>
        <DataStateBoundary
          state={state}
          onRetry={onRetry}
          preserveContent={preserveContent}
        >
          {children}
        </DataStateBoundary>
      </div>
      {summary ? <p className="sr-only">{summary}</p> : null}
    </section>
  )
}
