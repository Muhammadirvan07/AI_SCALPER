import { dashboardDataConfig } from '../config/dataSources'
import type {
  DashboardWebSocketEvent,
  RealtimeTransportState,
} from '../types/dashboardApi'
import { parseWebSocketEvent } from '../utils/realtimeGuards'

interface DashboardSocketHandlers {
  onEvent: (event: DashboardWebSocketEvent) => void
  onStateChange: (state: RealtimeTransportState, attempt: number) => void
}

export class DashboardWebSocketClient {
  private socket: WebSocket | null = null
  private reconnectTimer: number | null = null
  private stopped = true
  private attempt = 0
  private generation = 0

  constructor(private readonly handlers: DashboardSocketHandlers) {}

  start() {
    if (!this.stopped && this.socket) return
    this.stopped = false
    this.connect()
  }

  private connect() {
    if (this.stopped || this.socket) return
    const generation = ++this.generation
    this.handlers.onStateChange(
      this.attempt === 0 ? 'connecting' : 'reconnecting',
      this.attempt,
    )
    const socket = new WebSocket(dashboardDataConfig.websocketUrl)
    this.socket = socket

    socket.addEventListener('open', () => {
      if (generation !== this.generation || this.stopped) return
      this.attempt = 0
      this.handlers.onStateChange('connected', 0)
    })
    socket.addEventListener('message', (message) => {
      if (generation !== this.generation || typeof message.data !== 'string') return
      const event = parseWebSocketEvent(message.data)
      if (event) this.handlers.onEvent(event)
    })
    socket.addEventListener('close', () => {
      if (generation !== this.generation) return
      this.socket = null
      if (this.stopped) {
        this.handlers.onStateChange('disconnected', this.attempt)
        return
      }
      this.scheduleReconnect()
    })
    socket.addEventListener('error', () => {
      if (generation === this.generation) socket.close()
    })
  }

  private scheduleReconnect() {
    if (this.stopped || this.reconnectTimer !== null) return
    this.attempt += 1
    this.handlers.onStateChange('reconnecting', this.attempt)
    const baseDelay = Math.min(30_000, 1_000 * 2 ** Math.min(this.attempt - 1, 5))
    const jitter = Math.round(baseDelay * (Math.random() * 0.2 - 0.1))
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, Math.max(250, baseDelay + jitter))
  }

  stop() {
    this.stopped = true
    this.generation += 1
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    const socket = this.socket
    this.socket = null
    if (socket && socket.readyState < WebSocket.CLOSING) socket.close()
    this.handlers.onStateChange('disconnected', this.attempt)
  }
}
