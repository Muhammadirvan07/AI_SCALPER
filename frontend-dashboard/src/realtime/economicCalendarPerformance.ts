import type { RealtimeEvent } from './websocketTypes'

interface CalendarReceipt {
  receivedAt: number
  scheduledAt: string
}

const receipts = new Map<string, CalendarReceipt>()

export function markCalendarEventReceived(event: RealtimeEvent): void {
  if (!['calendar.event.released', 'calendar.event.revised'].includes(event.type)) return
  if (typeof event.data !== 'object' || event.data === null) return
  const id = Reflect.get(event.data, 'id')
  const scheduledAt = Reflect.get(event.data, 'scheduled_at')
  if (typeof id !== 'string' || typeof scheduledAt !== 'string' || Number.isNaN(Date.parse(scheduledAt))) return
  receipts.set(id, { receivedAt: performance.now(), scheduledAt })
}

export function measureCalendarFrontendRender(eventId: string): {
  websocketToRenderMs: number
  scheduledToFrontendRenderMs: number
} | null {
  const receipt = receipts.get(eventId)
  if (!receipt) return null
  receipts.delete(eventId)
  return {
    websocketToRenderMs: Math.max(0, performance.now() - receipt.receivedAt),
    scheduledToFrontendRenderMs: Math.max(0, Date.now() - Date.parse(receipt.scheduledAt)),
  }
}
