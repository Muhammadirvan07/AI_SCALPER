import { useSyncExternalStore } from 'react'

let current = Date.now()
let timer: ReturnType<typeof globalThis.setInterval> | null = null
const listeners = new Set<() => void>()

const subscribe = (listener: () => void) => {
  listeners.add(listener)
  if (timer === null) {
    timer = globalThis.setInterval(() => {
      current = Date.now()
      listeners.forEach((notify) => notify())
    }, 1_000)
  }
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0 && timer !== null) {
      globalThis.clearInterval(timer)
      timer = null
    }
  }
}

export function useEconomicCalendarClock() {
  return useSyncExternalStore(subscribe, () => current, () => current)
}
