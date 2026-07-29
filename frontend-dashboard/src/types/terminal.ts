export type TerminalPanelState =
  | 'loading'
  | 'connected'
  | 'stale'
  | 'partial'
  | 'disconnected'
  | 'empty'
  | 'error'

export type TerminalTone =
  | 'safe'
  | 'positive'
  | 'caution'
  | 'warning'
  | 'blocked'
  | 'neutral'
