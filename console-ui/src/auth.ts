// License Apache License 2.0


import { createContext, useContext } from 'react'
import { canUser, type AccessUser, type CaResource } from './access-policy'

export interface AuthUser extends AccessUser {
  id: number
  username: string
  displayName?: string | null
}

export const AuthContext = createContext<AuthUser | null>(null)
export const useCan = () => {
  const user = useContext(AuthContext)
  return (permission: string, ca?: CaResource, profile?: string) =>
    canUser(user, permission, ca, profile)
}
