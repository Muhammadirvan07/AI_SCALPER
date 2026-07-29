import { environment } from '../config/environment'
import { isApiErrorResponse, parseApiResponse } from './guards'
import type { ApiResponse } from './types'

export type ApiErrorKind =
  | 'network'
  | 'timeout'
  | 'safety'
  | 'unavailable'
  | 'conflict'
  | 'rate-limit'
  | 'validation'
  | 'http'
  | 'invalid-response'
  | 'aborted'

export class ApiClientError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number | null
  readonly code: string | null
  readonly requestId: string | null
  readonly details?: unknown

  constructor(
    message: string,
    kind: ApiErrorKind,
    status: number | null = null,
    code: string | null = null,
    requestId: string | null = null,
    details?: unknown,
  ) {
    super(message)
    this.name = 'ApiClientError'
    this.kind = kind
    this.status = status
    this.code = code
    this.requestId = requestId
    this.details = details
  }
}

interface RequestOptions<T> {
  signal?: AbortSignal
  timeoutMs?: number
  retries?: number
  validate: (candidate: unknown) => candidate is T
}

const requestId = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `frontend-${Date.now().toString(36)}`

const errorKindForStatus = (status: number, code: string | null): ApiErrorKind => {
  if (status === 403 || code === 'LIVE_TRADING_LOCKED') return 'safety'
  if (status === 409) return 'conflict'
  if (status === 429) return 'rate-limit'
  if (status === 422) return 'validation'
  if (status === 503) return 'unavailable'
  return 'http'
}

export class ApiClient {
  private readonly inflight = new Map<string, Promise<ApiResponse<unknown>>>()
  private readonly baseUrl: string
  private readonly defaultTimeoutMs: number
  private readonly defaultRetries: number
  private readonly fetcher: typeof fetch

  constructor(
    baseUrl = environment.apiBaseUrl,
    defaultTimeoutMs = environment.requestTimeoutMs,
    defaultRetries = environment.maximumRequestRetries,
    fetcher: typeof fetch = fetch,
  ) {
    this.baseUrl = baseUrl
    this.defaultTimeoutMs = defaultTimeoutMs
    this.defaultRetries = defaultRetries
    // Native browser fetch requires the Window/global receiver in some runtimes.
    // Binding here keeps injected test fetchers working and prevents an
    // "Illegal invocation" before the request reaches the network stack.
    this.fetcher = fetcher.bind(globalThis)
  }

  get<T>(path: string, options: RequestOptions<T>): Promise<ApiResponse<T>> {
    const key = `GET:${path}`
    const existing = this.inflight.get(key)
    if (existing) return existing as Promise<ApiResponse<T>>
    const promise = this.request(path, options)
    this.inflight.set(key, promise as Promise<ApiResponse<unknown>>)
    void promise.then(
      () => this.inflight.delete(key),
      () => this.inflight.delete(key),
    )
    return promise
  }

  private async request<T>(path: string, options: RequestOptions<T>): Promise<ApiResponse<T>> {
    const retries = options.retries ?? this.defaultRetries
    let attempt = 0
    while (true) {
      try {
        return await this.requestOnce(path, options)
      } catch (reason) {
        const error = reason instanceof ApiClientError
          ? reason
          : new ApiClientError('Backend AI_SCALPER tidak dapat dijangkau.', 'network')
        const retryable = error.kind === 'network' || error.kind === 'timeout' || (error.status !== null && error.status >= 500)
        if (!retryable || attempt >= retries || options.signal?.aborted) throw error
        attempt += 1
        await new Promise((resolve) => globalThis.setTimeout(resolve, 250 * 2 ** (attempt - 1)))
      }
    }
  }

  private async requestOnce<T>(path: string, options: RequestOptions<T>): Promise<ApiResponse<T>> {
    const controller = new AbortController()
    let timedOut = false
    const abortFromCaller = () => controller.abort(options.signal?.reason)
    options.signal?.addEventListener('abort', abortFromCaller, { once: true })
    const timeout = globalThis.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, options.timeoutMs ?? this.defaultTimeoutMs)

    try {
      const response = await this.fetcher(`${this.baseUrl}${path}`, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          'X-Request-ID': requestId(),
        },
      })
      const payload: unknown = await response.json().catch(() => null)
      if (!response.ok) {
        if (isApiErrorResponse(payload)) {
          throw new ApiClientError(
            payload.error.message,
            errorKindForStatus(response.status, payload.error.code),
            response.status,
            payload.error.code,
            payload.meta?.request_id ?? response.headers.get('x-request-id'),
            payload.error.details,
          )
        }
        throw new ApiClientError(
          `Backend mengembalikan HTTP ${response.status}.`,
          errorKindForStatus(response.status, null),
          response.status,
          null,
          response.headers.get('x-request-id'),
        )
      }
      const parsed = parseApiResponse(payload, options.validate)
      if (!parsed) {
        throw new ApiClientError(
          'Respons backend tidak sesuai kontrak API v1.',
          'invalid-response',
          response.status,
          'INVALID_RESPONSE',
          response.headers.get('x-request-id'),
        )
      }
      return parsed
    } catch (reason) {
      if (reason instanceof ApiClientError) throw reason
      if (controller.signal.aborted) {
        if (timedOut) throw new ApiClientError('Permintaan ke backend melewati batas waktu.', 'timeout')
        throw new ApiClientError('Permintaan dibatalkan.', 'aborted')
      }
      throw new ApiClientError('Backend unavailable. Could not connect to AI_SCALPER backend at 127.0.0.1:8000.', 'network')
    } finally {
      globalThis.clearTimeout(timeout)
      options.signal?.removeEventListener('abort', abortFromCaller)
    }
  }
}

export const apiClient = new ApiClient()
