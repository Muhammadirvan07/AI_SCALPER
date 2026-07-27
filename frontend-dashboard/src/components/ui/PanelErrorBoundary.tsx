import { Component, type ErrorInfo, type ReactNode } from 'react'
import { PanelState } from './PanelState'

interface PanelErrorBoundaryProps {
  children: ReactNode
}

interface PanelErrorBoundaryState {
  hasError: boolean
}

export class PanelErrorBoundary extends Component<
  PanelErrorBoundaryProps,
  PanelErrorBoundaryState
> {
  state: PanelErrorBoundaryState = { hasError: false }

  static getDerivedStateFromError(): PanelErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Panel dashboard gagal dirender', error, info)
  }

  render() {
    if (this.state.hasError) {
      return <PanelState state="error" />
    }

    return this.props.children
  }
}
