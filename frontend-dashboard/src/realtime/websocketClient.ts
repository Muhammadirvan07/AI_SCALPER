import { environment } from '../config/environment'
import { defaultSubscriptions, economicCalendarSymbolChannel, marketChannel, newsSymbolChannel } from './subscriptions'
import {
  parseRealtimeEvent,
  type ConnectionSnapshot,
  type RealtimeEvent,
  type WebSocketConnectionState,
} from './websocketTypes'

interface SocketMessageEvent {
  data: unknown
}

interface WebSocketLike {
  readyState: number
  onopen: (() => void) | null
  onmessage: ((event: SocketMessageEvent) => void) | null
  onerror: (() => void) | null
  onclose: (() => void) | null
  send(data: string): void
  close(code?: number, reason?: string): void
}

type SocketFactory = (url: string) => WebSocketLike

interface WebSocketClientOptions {
  url?: string
  createSocket?: SocketFactory
  onEvent: (event: RealtimeEvent) => void
  onConnectionChange: (snapshot: ConnectionSnapshot) => void
  heartbeatTimeoutMs?: number
  pingIntervalMs?: number
  maximumReconnectDelayMs?: number
}

const initialConnection = (): ConnectionSnapshot => ({
  state: 'CONNECTING',
  reconnectAttempt: 0,
  lastHeartbeatAt: null,
  lastEventAt: null,
  lastSuccessfulUpdate: null,
  subscribedChannels: [],
  retryAt: null,
  error: null,
})

export class SharedWebSocketClient {
  private socket: WebSocketLike | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private watchdogTimer: ReturnType<typeof setInterval> | null = null
  private stopped = true
  private lastSequence = 0
  private connection = initialConnection()
  private readonly desiredChannels = new Set<string>(defaultSubscriptions)
  private activeMarketChannel: string | null = null
  private activeNewsChannel: string | null = null
  private activeCalendarChannel: string | null = null
  private readonly url: string
  private readonly createSocket: SocketFactory
  private readonly heartbeatTimeoutMs: number
  private readonly pingIntervalMs: number
  private readonly maximumReconnectDelayMs: number
  private readonly options: WebSocketClientOptions

  constructor(options: WebSocketClientOptions) {
    this.options = options
    this.url = options.url ?? environment.websocketUrl
    this.createSocket = options.createSocket ?? ((url) => new WebSocket(url) as unknown as WebSocketLike)
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 35_000
    this.pingIntervalMs = options.pingIntervalMs ?? 20_000
    this.maximumReconnectDelayMs = options.maximumReconnectDelayMs ?? 30_000
  }

  start(): void {
    if (!this.stopped) return
    this.stopped = false
    if (typeof window !== 'undefined') {
      window.addEventListener('online', this.handleOnline)
      window.addEventListener('offline', this.handleOffline)
      document.addEventListener('visibilitychange', this.handleVisibility)
    }
    this.watchdogTimer = globalThis.setInterval(() => this.checkHeartbeat(), 5_000)
    this.connect()
  }

  stop(): void {
    this.stopped = true
    this.clearTimers()
    if (typeof window !== 'undefined') {
      window.removeEventListener('online', this.handleOnline)
      window.removeEventListener('offline', this.handleOffline)
      document.removeEventListener('visibilitychange', this.handleVisibility)
    }
    const socket = this.socket
    this.socket = null
    if (socket && socket.readyState < 2) socket.close(1000, 'Application cleanup')
  }

  subscribe(channels: string[]): void {
    const fresh = channels.filter((channel) => !this.desiredChannels.has(channel))
    fresh.forEach((channel) => this.desiredChannels.add(channel))
    if (fresh.length > 0) this.send({ action: 'subscribe', channels: fresh })
  }

  unsubscribe(channels: string[]): void {
    const active = channels.filter((channel) => this.desiredChannels.delete(channel))
    if (active.length > 0) this.send({ action: 'unsubscribe', channels: active })
  }

  setMarketSymbol(symbol: string | null): void {
    const next = symbol ? marketChannel(symbol) : null
    const nextNews = symbol ? newsSymbolChannel(symbol) : null
    const nextCalendar = symbol ? economicCalendarSymbolChannel(symbol) : null
    if (next === this.activeMarketChannel && nextNews === this.activeNewsChannel && nextCalendar === this.activeCalendarChannel) return
    if (this.activeMarketChannel) this.unsubscribe([this.activeMarketChannel])
    if (this.activeNewsChannel) this.unsubscribe([this.activeNewsChannel])
    if (this.activeCalendarChannel) this.unsubscribe([this.activeCalendarChannel])
    this.activeMarketChannel = next
    this.activeNewsChannel = nextNews
    this.activeCalendarChannel = nextCalendar
    if (next) this.subscribe([next])
    if (nextNews) this.subscribe([nextNews])
    if (nextCalendar) this.subscribe([nextCalendar])
  }

  private connect(): void {
    if (this.stopped || this.socket) return
    if (typeof navigator !== 'undefined' && navigator.onLine === false) {
      this.setState('OFFLINE', 'Browser sedang offline.')
      return
    }
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
      this.setState('RECONNECTING', null)
      return
    }
    this.setState(this.connection.reconnectAttempt > 0 ? 'RECONNECTING' : 'CONNECTING', null)
    try {
      const socket = this.createSocket(this.url)
      this.socket = socket
      socket.onopen = () => this.handleOpen(socket)
      socket.onmessage = (event) => this.handleMessage(event.data)
      socket.onerror = () => this.setState('ERROR', 'WebSocket mengalami kesalahan transport.')
      socket.onclose = () => this.handleClose(socket)
    } catch {
      this.socket = null
      this.scheduleReconnect('WebSocket tidak dapat dibuat.')
    }
  }

  private handleOpen(socket: WebSocketLike): void {
    if (this.socket !== socket) return
    this.lastSequence = 0
    this.connection = {
      ...this.connection,
      state: 'CONNECTED',
      reconnectAttempt: 0,
      retryAt: null,
      error: null,
    }
    this.emitConnection()
    this.send({ action: 'subscribe', channels: [...this.desiredChannels] })
    this.pingTimer = globalThis.setInterval(() => this.send({ action: 'ping', channels: [] }), this.pingIntervalMs)
  }

  private handleMessage(raw: unknown): void {
    const event = parseRealtimeEvent(raw)
    if (!event) {
      this.connection = { ...this.connection, error: 'Event WebSocket invalid diabaikan.' }
      this.emitConnection()
      return
    }
    if (event.sequence <= this.lastSequence) return
    this.lastSequence = event.sequence
    const heartbeat = event.type === 'connection.heartbeat' || event.type === 'connection.pong'
    this.connection = {
      ...this.connection,
      state: 'CONNECTED',
      lastEventAt: event.timestamp,
      lastHeartbeatAt: heartbeat ? event.timestamp : this.connection.lastHeartbeatAt,
      lastSuccessfulUpdate: event.timestamp,
      error: event.type === 'error' ? 'Backend mengirim event error.' : null,
    }
    if (event.type === 'subscription.updated' && typeof event.data === 'object' && event.data !== null) {
      const subscribed = Reflect.get(event.data, 'subscribed')
      if (Array.isArray(subscribed) && subscribed.every((item) => typeof item === 'string')) {
        this.connection.subscribedChannels = [...subscribed]
      }
    }
    this.emitConnection()
    this.options.onEvent(event)
  }

  private handleClose(socket: WebSocketLike): void {
    if (this.socket !== socket) return
    this.socket = null
    if (this.pingTimer) globalThis.clearInterval(this.pingTimer)
    this.pingTimer = null
    if (!this.stopped) this.scheduleReconnect('Koneksi WebSocket terputus.')
  }

  private scheduleReconnect(message: string): void {
    if (this.stopped || this.reconnectTimer) return
    if (typeof navigator !== 'undefined' && navigator.onLine === false) {
      this.setState('OFFLINE', message)
      return
    }
    const attempt = this.connection.reconnectAttempt + 1
    const delay = Math.min(this.maximumReconnectDelayMs, 1_000 * 2 ** Math.min(attempt - 1, 5))
    this.connection = {
      ...this.connection,
      state: 'RECONNECTING',
      reconnectAttempt: attempt,
      retryAt: new Date(Date.now() + delay).toISOString(),
      error: message,
    }
    this.emitConnection()
    this.reconnectTimer = globalThis.setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, delay)
  }

  private checkHeartbeat(): void {
    if (this.connection.state !== 'CONNECTED') return
    const heartbeatMs = this.connection.lastHeartbeatAt ? Date.parse(this.connection.lastHeartbeatAt) : 0
    const eventMs = this.connection.lastEventAt ? Date.parse(this.connection.lastEventAt) : 0
    const latest = Math.max(heartbeatMs, eventMs)
    if (latest > 0 && Date.now() - latest > this.heartbeatTimeoutMs) {
      this.setState('DELAYED', 'Heartbeat WebSocket terlambat.')
      this.send({ action: 'ping', channels: [] })
    }
  }

  private send(message: { action: string; channels: string[] }): void {
    if (this.socket?.readyState !== 1) return
    this.socket.send(JSON.stringify(message))
  }

  private setState(state: WebSocketConnectionState, error: string | null): void {
    this.connection = { ...this.connection, state, error }
    this.emitConnection()
  }

  private emitConnection(): void {
    this.options.onConnectionChange(structuredClone(this.connection))
  }

  private clearTimers(): void {
    if (this.reconnectTimer) globalThis.clearTimeout(this.reconnectTimer)
    if (this.pingTimer) globalThis.clearInterval(this.pingTimer)
    if (this.watchdogTimer) globalThis.clearInterval(this.watchdogTimer)
    this.reconnectTimer = null
    this.pingTimer = null
    this.watchdogTimer = null
  }

  private readonly handleOnline = () => {
    if (this.connection.state === 'OFFLINE') this.connect()
  }

  private readonly handleOffline = () => {
    if (this.reconnectTimer) globalThis.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
    this.socket?.close(1000, 'Browser offline')
    this.socket = null
    this.setState('OFFLINE', 'Browser sedang offline.')
  }

  private readonly handleVisibility = () => {
    if (document.visibilityState === 'visible' && !this.socket && !this.stopped) this.connect()
  }
}
