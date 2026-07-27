const currencyFormatter = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
})

export const formatCurrency = (value: number, showSign = false) => {
  const formatted = currencyFormatter.format(Math.abs(value))
  if (!showSign || value === 0) return value < 0 ? `-${formatted}` : formatted
  return `${value > 0 ? '+' : '-'}${formatted}`
}

export const formatPercent = (value: number, digits = 1, showSign = false) => {
  const sign = showSign && value > 0 ? '+' : ''
  return `${sign}${value.toFixed(digits)}%`
}

export const formatPrice = (value: number, precision: number) =>
  new Intl.NumberFormat('en-US', {
    minimumFractionDigits: precision,
    maximumFractionDigits: precision,
  }).format(value)

export const formatTime = (isoDate: string) =>
  new Intl.DateTimeFormat('id-ID', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(isoDate))

export const formatDateTime = (isoDate: string) =>
  new Intl.DateTimeFormat('id-ID', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(isoDate))
