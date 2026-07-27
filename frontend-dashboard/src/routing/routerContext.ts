import { createContext, useContext } from 'react'

export interface RouterContextValue {
  pathname: string
  navigate: (to: string, options?: { replace?: boolean }) => void
}

export const RouterContext = createContext<RouterContextValue | null>(null)

const useRouter = () => {
  const value = useContext(RouterContext)
  if (!value) throw new Error('RouterProvider belum terpasang.')
  return value
}

export const useNavigate = () => useRouter().navigate

export const useLocation = () => {
  const { pathname } = useRouter()
  return { pathname }
}
