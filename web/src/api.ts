export type JsonObject = Record<string, unknown>

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

export class ApiClient {
  csrf = ''

  async requestWithResponse<T>(path: string, init: RequestInit = {}): Promise<{ data: T; response: Response }> {
    const headers = new Headers(init.headers)
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const method = (init.method || 'GET').toUpperCase()
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && this.csrf) headers.set('X-CSRF-Token', this.csrf)
    const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
    if (!response.ok) {
      let detail = { error: { code: 'request_failed', message: `请求失败 (${response.status})` } }
      try { detail = await response.json() } catch { /* use stable fallback */ }
      throw new ApiError(response.status, detail.error.code, detail.error.message)
    }
    const data = response.status === 204 ? undefined as T : await response.json() as T
    return { data, response }
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    return (await this.requestWithResponse<T>(path, init)).data
  }

  get<T>(path: string) { return this.request<T>(path) }
  getResponse<T>(path: string) { return this.requestWithResponse<T>(path) }
  post<T>(path: string, value: unknown = {}) {
    return this.request<T>(path, { method: 'POST', body: JSON.stringify(value) })
  }
  put<T>(path: string, value: unknown, etag: string) {
    return this.request<T>(path, { method: 'PUT', headers: { 'If-Match': etag }, body: JSON.stringify(value) })
  }
  patch<T>(path: string, value: unknown) {
    return this.request<T>(path, { method: 'PATCH', body: JSON.stringify(value) })
  }
}
