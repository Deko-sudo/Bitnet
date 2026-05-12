import axios from 'axios'
import { useAuthStore } from '@/store/authStore'

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (!error.response) {
      return Promise.reject(error)
    }
    if (error.response.status === 401) {
      const url = error.config?.url || ''
      const isAuthEndpoint = url.startsWith('/auth/login') || url.startsWith('/auth/register') || url.startsWith('/auth/me')
      if (!isAuthEndpoint) {
        useAuthStore.getState().logout()
      }
    }
    return Promise.reject(error)
  }
)