// License Apache License 2.0


import { useI18n } from './i18n'
import React, { useState, useEffect, useCallback } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { Button, Result, Spin } from 'antd'
import ApplicationHeader from './components/ApplicationHeader'
import MainLayout from './layouts/MainLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import CaList from './pages/ca/CaList'
import CaEnrollmentRecords from './pages/ca/CaEnrollmentRecords'
import CaDetail from './pages/ca/CaDetail'
import CertList from './pages/cert/CertList'
import CertEnroll from './pages/cert/CertEnroll'
import CrlManage from './pages/crl/CrlManage'
import ProfileList from './pages/profile/ProfileList'
import ProfileEditor from './pages/profile/ProfileEditor'
import SignerList from './pages/signer/SignerList'
import RequestorList from './pages/requestor/RequestorList'
import PublisherList from './pages/publisher/PublisherList'
import KeypairGenList from './pages/keypairGen/KeypairGenList'
import SystemStatus from './pages/system/SystemStatus'
import DbSchemaManage from './pages/dbschema/DbSchemaManage'
import AuditList from './pages/audit/AuditList'
import { authApi, authenticationRequiredEvent } from './api/client'
import { AuthContext, type AuthUser } from './auth'
import { landingPath } from './access-policy'
import { navigationPermission } from './navigation'
import Users from './pages/access/Users'
import Roles from './pages/access/Roles'
import PasswordChange from './pages/access/PasswordChange'
import MyAccount from './pages/access/MyAccount'

const can = (user: AuthUser, permission: string) =>
  permission.split('|').some((code) => user.permissions.includes(code))

const Guard: React.FC<{ user: AuthUser; permission: string; children: React.ReactNode }> = ({
  user,
  permission,
  children,
}) => {
  const { t } = useI18n()
  return can(user, permission) ? (
    <>{children}</>
  ) : (
    <Result status="403" title={t('Permission denied')} />
  )
}

const App: React.FC = () => {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [unavailable, setUnavailable] = useState(false)

  const checkSession = useCallback(() => {
    setLoading(true)
    setUnavailable(false)
    return authApi
      .get('/api/auth/me')
      .then((res) => {
        if (res.data.success) setUser(res.data.data)
      })
      .catch((error) => {
        setUser(null)
        setUnavailable(error.response?.status !== 401)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    void checkSession()
  }, [checkSession])
  useEffect(() => {
    const requireLogin = () => {
      setUser(null)
      setUnavailable(false)
    }
    window.addEventListener(authenticationRequiredEvent, requireLogin)
    return () => window.removeEventListener(authenticationRequiredEvent, requireLogin)
  }, [])

  if (loading) return <Spin fullscreen tip={t('Connecting to management service…')} />
  if (unavailable)
    return (
      <>
        <ApplicationHeader />
        <Result
          status="error"
          title={t('Management service unavailable')}
          subTitle={t('Check that the service and database are ready, then retry.')}
          extra={<Button onClick={() => void checkSession()}>{t('Retry connection')}</Button>}
        />
      </>
    )

  if (!user) {
    return (
      <Login
        onSuccess={(next) => {
          setUser(next)
          navigate(landingPath(next), { replace: true })
        }}
      />
    )
  }

  return (
    <AuthContext.Provider value={user}>
      <MainLayout user={user} onLogout={() => setUser(null)}>
        {user.passwordChangeRequired ? (
          <PasswordChange />
        ) : (
          <Routes>
            <Route path="/" element={<Navigate to={landingPath(user)} replace />} />
            <Route
              path="/dashboard"
              element={
                <Guard user={user} permission={navigationPermission('/dashboard')}>
                  <Dashboard />
                </Guard>
              }
            />
            <Route
              path="/ca"
              element={
                <Guard user={user} permission={navigationPermission('/ca')}>
                  <CaList />
                </Guard>
              }
            />
            <Route
              path="/ca/operations/enrollments"
              element={
                <Guard user={user} permission="CA_IMPORT|CA_ISSUE_SUBCA">
                  <CaEnrollmentRecords />
                </Guard>
              }
            />
            <Route
              path="/ca/:name"
              element={
                <Guard user={user} permission="CA_READ">
                  <CaDetail />
                </Guard>
              }
            />
            <Route
              path="/cert"
              element={
                <Guard user={user} permission={navigationPermission('/cert')}>
                  <CertList />
                </Guard>
              }
            />
            <Route
              path="/cert/enroll"
              element={
                <Guard user={user} permission={navigationPermission('/cert/enroll')}>
                  <CertEnroll />
                </Guard>
              }
            />
            <Route
              path="/crl"
              element={
                <Guard user={user} permission={navigationPermission('/crl')}>
                  <CrlManage />
                </Guard>
              }
            />
            <Route
              path="/profile"
              element={
                <Guard user={user} permission={navigationPermission('/profile')}>
                  <ProfileList />
                </Guard>
              }
            />
            <Route
              path="/profile/:name"
              element={
                <Guard user={user} permission="PROFILE_CONFIG_READ">
                  <ProfileEditor />
                </Guard>
              }
            />
            <Route
              path="/signer"
              element={
                <Guard user={user} permission={navigationPermission('/signer')}>
                  <SignerList />
                </Guard>
              }
            />
            <Route
              path="/requestor"
              element={
                <Guard user={user} permission={navigationPermission('/requestor')}>
                  <RequestorList />
                </Guard>
              }
            />
            <Route
              path="/publisher"
              element={
                <Guard user={user} permission={navigationPermission('/publisher')}>
                  <PublisherList />
                </Guard>
              }
            />
            <Route
              path="/keypairgen"
              element={
                <Guard user={user} permission={navigationPermission('/keypairgen')}>
                  <KeypairGenList />
                </Guard>
              }
            />
            <Route
              path="/system"
              element={
                <Guard user={user} permission={navigationPermission('/system')}>
                  <SystemStatus />
                </Guard>
              }
            />
            <Route
              path="/dbschema"
              element={
                <Guard user={user} permission={navigationPermission('/dbschema')}>
                  <DbSchemaManage />
                </Guard>
              }
            />
            <Route
              path="/audit"
              element={
                <Guard user={user} permission={navigationPermission('/audit')}>
                  <AuditList />
                </Guard>
              }
            />
            <Route
              path="/access/users"
              element={
                <Guard user={user} permission={navigationPermission('/access/users')}>
                  <Users />
                </Guard>
              }
            />
            <Route
              path="/access/roles"
              element={
                <Guard user={user} permission={navigationPermission('/access/roles')}>
                  <Roles />
                </Guard>
              }
            />
            <Route path="/account/password" element={<PasswordChange />} />
            <Route
              path="/account"
              element={
                <MyAccount
                  onDisplayNameSaved={(displayName) => {
                    setUser((current) =>
                      current?.id === user.id ? { ...current, displayName } : current,
                    )
                  }}
                />
              }
            />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        )}
      </MainLayout>
    </AuthContext.Provider>
  )
}

export default App
