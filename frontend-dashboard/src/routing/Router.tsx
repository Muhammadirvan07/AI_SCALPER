import {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from 'react'
import { RouterContext, useNavigate } from './routerContext'

const normalizedPath = (value: string) => {
  const path = value.split(/[?#]/, 1)[0] || '/'
  return path.length > 1 ? path.replace(/\/+$/, '') : path
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [pathname, setPathname] = useState(() => normalizedPath(window.location.pathname))

  useEffect(() => {
    const onPopState = () => setPathname(normalizedPath(window.location.pathname))
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const navigate = useCallback((to: string, options?: { replace?: boolean }) => {
    const target = normalizedPath(to)
    if (target === normalizedPath(window.location.pathname)) return
    if (options?.replace) window.history.replaceState(null, '', target)
    else window.history.pushState(null, '', target)
    setPathname(target)
  }, [])

  const value = useMemo(() => ({ pathname, navigate }), [navigate, pathname])
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

interface LinkProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  to: string
}

export function Link({ to, onClick, target, children, ...props }: LinkProps) {
  const navigate = useNavigate()
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event)
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      target === '_blank'
    ) {
      return
    }
    event.preventDefault()
    navigate(to)
  }
  return (
    <a href={to} target={target} onClick={handleClick} {...props}>
      {children}
    </a>
  )
}

interface NavLinkProps extends Omit<LinkProps, 'className'> {
  className?: string | ((state: { isActive: boolean }) => string)
}

export function NavLink({ to, className, ...props }: NavLinkProps) {
  const { pathname } = useContext(RouterContext) ?? { pathname: '/' }
  const isActive = pathname === normalizedPath(to)
  return (
    <Link
      to={to}
      className={typeof className === 'function' ? className({ isActive }) : className}
      aria-current={isActive ? 'page' : undefined}
      {...props}
    />
  )
}
