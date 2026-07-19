<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import {
  Activity, BookOpen, Boxes, Braces, Check, CheckCircle2, ChevronRight,
  Clipboard, Clock3, Database, Eye, FileJson2, Gauge, HeartPulse, KeyRound,
  Layers3, LayoutDashboard, Link2, ListChecks, LogOut, Network, Pencil,
  Play, Plus, RefreshCw, Save, Search, Send, Server, Settings, ShieldCheck,
  SlidersHorizontal, Trash2, Workflow, X,
} from '@lucide/vue'
import { ApiClient, ApiError } from './api'
import type {
  Capacity, HealthRecord, ManagedResource, NodeItem, OutputItem, Page, Session, Source,
} from './types'

type View = 'overview' | 'sources' | 'nodes' | 'rules' | 'outputs' | 'settings' | 'guide'
type RuleTab = 'collections' | 'templates' | 'pipelines'
type Modal = 'source' | 'collection' | 'pipeline' | 'template' | 'output' | 'output-policy' | 'node' | 'archive-source' | null

const api = new ApiClient()
const setupChecked = ref(false)
const initialized = ref(true)
const session = ref<Session | null>(null)
const active = ref<View>('overview')
const ruleTab = ref<RuleTab>('collections')
const modal = ref<Modal>(null)
const loading = ref(false)
const error = ref('')
const toast = ref('')
const authNotice = ref('')
const secretPath = ref('')
const query = ref('')

const sources = ref<Source[]>([])
const nodes = ref<NodeItem[]>([])
const collections = ref<ManagedResource[]>([])
const pipelines = ref<ManagedResource[]>([])
const templates = ref<ManagedResource[]>([])
const outputs = ref<OutputItem[]>([])
const capacity = ref<Capacity | null>(null)

const healthFilter = ref('all')
const sourceFilter = ref('all')
const protocolFilter = ref('all')
const selectedNodeIDs = ref<Set<string>>(new Set())
const selectedNode = ref<NodeItem | null>(null)
const healthRecords = ref<HealthRecord[]>([])
const editingID = ref('')
const editingETag = ref('')
const selectedOutput = ref<OutputItem | null>(null)
const selectedSource = ref<Source | null>(null)

const auth = reactive({
  username: '', password: '', confirmPassword: '', showPassword: false,
  setupToken: '', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Shanghai',
})
const setupCommand = 'docker compose run --rm --no-deps proxyloom bootstrap-token'
const sourceForm = reactive({
	display_name: '', type: 'remote', url: '', headers: '', proxy_url: '', clear_proxy: false,
	proxy_configured: false, masked_proxy: '', content: '', input_format: 'auto', timeout_seconds: 30,
	refresh_interval_seconds: 3600, private_network_authorized: false, health_filter_enabled: false,
})
const collectionForm = reactive({ display_name: '', source_ids: [] as string[] })
const pipelineForm = reactive({ display_name: '', operations: '[]' })
const defaultTemplateContent = `{
  "log": { "level": "info" },
  "outbounds": [
    { "type": "selector", "tag": "Select", "outbounds": ["\${PROXYLOOM_NODES}"] },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "Select" }
}`
const templateForm = reactive({
  display_name: '', source_type: 'remote', url: '', headers: '',
  refresh_interval_seconds: 3600, private_network_authorized: false, content: defaultTemplateContent,
})
const outputForm = reactive({
  display_name: '', collection_id: '', pipeline_id: '', template_id: '',
  target_profile: 'momo-1.2.1-sing-box-1.12.25', output_shape: 'full_config',
  health_filter_enabled: true, minimum_nodes: 1, maximum_drop_ratio: 0.5,
})
const passwordForm = reactive({ current_password: '', new_password: '', confirm_password: '' })

const navigation = [
  { id: 'overview' as View, label: '总览', icon: LayoutDashboard },
  { id: 'sources' as View, label: '订阅管理', icon: Link2 },
  { id: 'nodes' as View, label: '节点健康', icon: HeartPulse },
  { id: 'rules' as View, label: '聚合与规则', icon: Workflow },
  { id: 'outputs' as View, label: '输出订阅', icon: Send },
  { id: 'settings' as View, label: '设置', icon: Settings },
  { id: 'guide' as View, label: '使用说明', icon: BookOpen },
]

const pageTitle = computed(() => navigation.find(item => item.id === active.value)?.label || '')
const secretFullURL = computed(() => secretPath.value ? new URL(secretPath.value, window.location.origin).toString() : '')
const activeCount = computed(() => {
  if (active.value === 'sources') return sources.value.length
  if (active.value === 'nodes') return nodes.value.length
  if (active.value === 'outputs') return outputs.value.length
  return ''
})
const addLabel = computed(() => {
  if (active.value === 'sources') return '添加订阅'
  if (active.value === 'outputs') return '新建输出'
  if (active.value === 'rules') return ruleTab.value === 'collections' ? '新建聚合' : ruleTab.value === 'templates' ? '添加规则模板' : '新建处理脚本'
  return ''
})
const healthyNodes = computed(() => nodes.value.filter(item => item.health === 'healthy' && !item.stale).length)
const unhealthyNodes = computed(() => nodes.value.filter(item => item.health === 'unhealthy').length)
const uncheckedNodes = computed(() => nodes.value.filter(item => ['unchecked', 'checking'].includes(item.health)).length)
const availableNodes = computed(() => nodes.value.filter(item => !item.stale && !['unhealthy', 'disabled'].includes(item.health)).length)
const healthRate = computed(() => nodes.value.length ? Math.round(healthyNodes.value * 100 / nodes.value.length) : 0)
const sourceIssues = computed(() => sources.value.filter(item => item.stale || ['degraded', 'unhealthy'].includes(item.health)))
const sourceProtocols = computed(() => [...new Set(nodes.value.map(item => item.protocol))].sort())
const healthCounts = computed(() => {
  const result: Record<string, number> = { all: nodes.value.length }
  for (const item of nodes.value) result[item.health] = (result[item.health] || 0) + 1
  return result
})

const filteredSources = computed(() => filterByQuery(sources.value, item => `${item.display_name} ${item.masked_location || ''} ${item.health}`))
const filteredNodes = computed(() => filterByQuery(nodes.value.filter(item =>
  (healthFilter.value === 'all' || item.health === healthFilter.value) &&
  (sourceFilter.value === 'all' || item.source_id === sourceFilter.value) &&
  (protocolFilter.value === 'all' || item.protocol === protocolFilter.value)
), item => `${item.original_name} ${item.protocol} ${sourceName(item.source_id)} ${item.health}`))
const filteredCollections = computed(() => filterByQuery(collections.value, item => item.display_name))
const filteredPipelines = computed(() => filterByQuery(pipelines.value, item => item.display_name))
const filteredTemplates = computed(() => filterByQuery(templates.value, item => item.display_name))
const filteredOutputs = computed(() => filterByQuery(outputs.value, item => `${item.display_name} ${item.target_profile}`))

function filterByQuery<T>(items: T[], text: (item: T) => string) {
  const needle = query.value.trim().toLocaleLowerCase()
  return needle ? items.filter(item => text(item).toLocaleLowerCase().includes(needle)) : items
}

function sourceName(id: string) { return sources.value.find(item => item.id === id)?.display_name || id.slice(0, 8) }
function collectionName(id: string) { return collections.value.find(item => item.id === id)?.display_name || id.slice(0, 8) }
function templateName(id: string | null) { return id ? templates.value.find(item => item.id === id)?.display_name || id.slice(0, 8) : '不使用模板' }
function memberCount(item: ManagedResource) { return Array.isArray(item.configuration.members) ? item.configuration.members.filter(member => (member as { enabled?: boolean }).enabled !== false).length : 0 }
function operationCount(item: ManagedResource) { return Array.isArray(item.configuration.operations) ? item.configuration.operations.length : 0 }
function sourceNodeCount(id: string) { return nodes.value.filter(item => item.source_id === id).length }
function isRemoteTemplate(item: ManagedResource) { return item.configuration.source_type === 'remote' }
function templateSummary(item: ManagedResource) {
  if (!isRemoteTemplate(item)) return '内联 sing-box 完整配置'
  const location = typeof item.configuration.masked_location === 'string' ? item.configuration.masked_location : '远程 URL'
  return `${location} · ${formatInterval(Number(item.configuration.refresh_interval_seconds || 0))}刷新`
}
function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '-' : new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(date)
}
function formatInterval(seconds: number) {
  if (!seconds) return '手动'
  if (seconds >= 3600 && seconds % 3600 === 0) return `每 ${seconds / 3600} 小时`
  return `每 ${Math.max(1, Math.round(seconds / 60))} 分钟`
}
function healthLabel(value: string, stale = false) {
  if (stale) return '已过期'
  return ({ healthy: '健康', degraded: '不稳定', unhealthy: '不可用', unchecked: '待检查', checking: '检查中', unsupported: '交由客户端检查', disabled: '已停用', unknown: '未知', active: '正常', ready: '可用' } as Record<string, string>)[value] || value
}
function statusClass(value: string, stale = false) {
  if (stale) return 'status stale'
  if (['healthy', 'ready', 'active', 'succeeded'].includes(value)) return 'status healthy'
  if (['unhealthy', 'failed', 'dead'].includes(value)) return 'status unhealthy'
  if (['degraded', 'suppressed'].includes(value)) return 'status warning'
  return 'status neutral'
}
function outputProfile(value: string) {
  if (value.startsWith('momo-')) return 'Momo / sing-box 1.12'
  return value.replace('sing-box-', 'sing-box ')
}

async function initialize() {
  try {
    const status = await api.get<{ administrator_initialized: boolean }>('/api/v1/setup/status')
    initialized.value = status.administrator_initialized
    if (!initialized.value && !auth.username) auth.username = 'admin'
    if (initialized.value) {
      try {
        acceptSession(await api.get<Session>('/api/v1/session'))
        await loadAll()
      } catch (cause) {
        if (!(cause instanceof ApiError) || cause.status !== 401) throw cause
      }
    }
  } catch (cause) { showError(cause) } finally { setupChecked.value = true }
}

function acceptSession(value: Session) { session.value = value; api.csrf = value.csrf_token }

async function login() {
  await perform(async () => {
    acceptSession(await api.post<Session>('/api/v1/session', { username: auth.username, password: auth.password }))
    auth.password = ''
    authNotice.value = ''
    await loadAll()
  })
}

async function setupAdministrator() {
  if (!validateSetupForm()) return
  await perform(async () => {
    const value = await api.request<Session>('/api/v1/setup/admin', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-ProxyLoom-Setup-Token': auth.setupToken },
      body: JSON.stringify({ username: auth.username, password: auth.password, timezone: auth.timezone }),
    })
    initialized.value = true
    acceptSession(value)
    auth.password = ''
    auth.confirmPassword = ''
    auth.setupToken = ''
    await loadAll()
  })
}

function validateSetupForm() {
  const usernameBytes = new TextEncoder().encode(auth.username.trim()).length
  const passwordBytes = new TextEncoder().encode(auth.password).length
  if (usernameBytes < 3 || usernameBytes > 64) {
    error.value = '用户名需要包含 3–64 个字节，建议直接使用 admin。'
    return false
  }
  if (passwordBytes < 1 || passwordBytes > 1024) {
    error.value = '密码不能为空，且不能超过 1024 字节。'
    return false
  }
  if (auth.password !== auth.confirmPassword) {
    error.value = '两次输入的密码不一致。'
    return false
  }
  if (!auth.setupToken.trim().startsWith('plst1_')) {
    error.value = '初始化令牌格式不正确，应以 plst1_ 开头。'
    return false
  }
  if (!auth.timezone.trim() || new TextEncoder().encode(auth.timezone.trim()).length > 64) {
    error.value = '时区不能为空，且不能超过 64 字节。'
    return false
  }
  return true
}

async function copySetupCommand() {
  try {
    await navigator.clipboard.writeText(setupCommand)
  } catch {
    const input = document.createElement('textarea')
    input.value = setupCommand
    input.style.position = 'fixed'
    input.style.opacity = '0'
    document.body.appendChild(input)
    input.select()
    document.execCommand('copy')
    input.remove()
  }
  authNotice.value = '令牌生成命令已复制。'
}

async function logout() {
  await perform(async () => {
    await api.request<void>('/api/v1/session', { method: 'DELETE' })
    session.value = null
    api.csrf = ''
  })
}

async function loadAll() {
  const [allSources, allNodes, collectionPage, pipelinePage, templatePage, outputPage, health] = await Promise.all([
    loadAllPages<Source>('/api/v1/sources'), loadAllPages<NodeItem>('/api/v1/nodes'),
    api.get<Page<ManagedResource>>('/api/v1/collections'), api.get<Page<ManagedResource>>('/api/v1/pipelines'),
    api.get<Page<ManagedResource>>('/api/v1/templates'), api.get<Page<OutputItem>>('/api/v1/outputs'),
    api.get<Capacity>('/api/v1/health/capacity'),
  ])
  sources.value = allSources
  nodes.value = allNodes
  collections.value = collectionPage.items
  pipelines.value = pipelinePage.items
  templates.value = templatePage.items
  outputs.value = outputPage.items
  capacity.value = health
}

async function loadAllPages<T>(path: string): Promise<T[]> {
  const items: T[] = []
  let cursor: string | null = null
  for (let pageNumber = 0; pageNumber < 1000; pageNumber++) {
    const cursorQuery: string = cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''
    const page: Page<T> = await api.get<Page<T>>(`${path}${path.includes('?') ? '&' : '?'}limit=200${cursorQuery}`)
    items.push(...page.items)
    if (!page.page.has_more) return items
    if (!page.page.next_cursor || page.page.next_cursor === cursor) throw new Error('分页游标无效，无法继续加载')
    cursor = page.page.next_cursor
  }
  throw new Error('数据页数超过安全上限')
}

async function refreshData() { await perform(loadAll, '数据已刷新') }

function switchView(view: View) { active.value = view; query.value = '' }

function openCreate() {
  if (active.value === 'sources') openSourceCreate()
  else if (active.value === 'outputs') { resetOutputForm(); modal.value = 'output' }
  else if (active.value === 'rules' && ruleTab.value === 'collections') openCollectionCreate()
  else if (active.value === 'rules' && ruleTab.value === 'templates') { resetTemplateForm(); modal.value = 'template' }
  else if (active.value === 'rules') openPipelineCreate()
}

function openSourceCreate() { editingID.value = ''; editingETag.value = ''; resetSourceForm(); modal.value = 'source' }

async function openSourceEdit(source: Source) {
  await perform(async () => {
    const { data, response } = await api.getResponse<Source>(`/api/v1/sources/${source.id}`)
    editingID.value = source.id
    editingETag.value = response.headers.get('ETag') || ''
    sourceForm.display_name = data.display_name
    sourceForm.type = data.configuration?.type || 'remote'
    sourceForm.url = ''
		sourceForm.headers = ''
		sourceForm.proxy_url = ''
		sourceForm.clear_proxy = false
		sourceForm.proxy_configured = data.configuration?.proxy_configured || false
		sourceForm.masked_proxy = data.masked_proxy || ''
		sourceForm.content = ''
    sourceForm.input_format = data.configuration?.input_format || 'auto'
		sourceForm.refresh_interval_seconds = data.configuration?.refresh_interval_seconds ?? 3600
		sourceForm.timeout_seconds = data.configuration?.timeout_seconds ?? 30
    sourceForm.private_network_authorized = data.configuration?.private_network_authorized || false
    sourceForm.health_filter_enabled = data.configuration?.health_filter_enabled || false
    modal.value = 'source'
  })
}

async function saveSource() {
  await perform(async () => {
    if (!editingID.value) {
      const payload: Record<string, unknown> = {
        display_name: sourceForm.display_name, type: sourceForm.type, input_format: sourceForm.input_format,
        output_format: 'same', minimum_nodes: 1, maximum_drop_ratio: 0.5,
			refresh_interval_seconds: sourceForm.type === 'remote' ? sourceForm.refresh_interval_seconds : 0,
			timeout_seconds: sourceForm.type === 'remote' ? sourceForm.timeout_seconds : 0,
        private_network_authorized: sourceForm.private_network_authorized,
        health_filter_enabled: sourceForm.health_filter_enabled,
      }
		if (sourceForm.type === 'remote') payload.url = sourceForm.url
		if (sourceForm.type === 'remote' && sourceForm.proxy_url) payload.proxy_url = sourceForm.proxy_url
      else payload.content = sourceForm.content
      if (sourceForm.type === 'remote' && sourceForm.headers.trim()) {
        const headers = JSON.parse(sourceForm.headers)
        if (!headers || Array.isArray(headers) || typeof headers !== 'object') throw new Error('请求头必须是 JSON 对象')
        payload.headers = headers
      }
      const result = await api.post<{ job_id: string; subscription_url: string }>('/api/v1/sources', payload)
      secretPath.value = result.subscription_url
      modal.value = null
      await pollJob(result.job_id, '订阅刷新')
    } else {
      const payload: Record<string, unknown> = {
        display_name: sourceForm.display_name, input_format: sourceForm.input_format,
			refresh_interval_seconds: sourceForm.type === 'remote' ? sourceForm.refresh_interval_seconds : 0,
			timeout_seconds: sourceForm.type === 'remote' ? sourceForm.timeout_seconds : 0,
        private_network_authorized: sourceForm.private_network_authorized,
        health_filter_enabled: sourceForm.health_filter_enabled,
      }
		if (sourceForm.type === 'remote' && sourceForm.url) payload.url = sourceForm.url
		if (sourceForm.type === 'remote' && sourceForm.proxy_url) payload.proxy_url = sourceForm.proxy_url
		else if (sourceForm.type === 'remote' && sourceForm.clear_proxy) payload.proxy_url = null
      if (sourceForm.type === 'remote' && sourceForm.headers.trim()) {
        const headers = JSON.parse(sourceForm.headers)
        if (!headers || Array.isArray(headers) || typeof headers !== 'object') throw new Error('请求头必须是 JSON 对象')
        payload.headers = headers
      }
      if (sourceForm.type !== 'remote' && sourceForm.content) payload.content = sourceForm.content
      const result = await api.request<{ job_id: string }>(`/api/v1/sources/${editingID.value}`, {
        method: 'PATCH', headers: { 'If-Match': editingETag.value }, body: JSON.stringify(payload),
      })
      modal.value = null
      await pollJob(result.job_id, '订阅更新')
    }
    await loadAll()
  }, editingID.value ? '订阅已更新' : '')
}

async function refreshSource(source: Source) {
  await perform(async () => {
    const result = await api.post<{ job_id: string }>(`/api/v1/sources/${source.id}/refresh`)
    await pollJob(result.job_id, `${source.display_name} 刷新`)
    await loadAll()
  })
}

async function createSourceToken(source: Source) {
  await perform(async () => {
    const result = await api.post<{ subscription_url: string }>(`/api/v1/sources/${source.id}/tokens`)
    secretPath.value = result.subscription_url
  })
}

async function confirmArchiveSource() {
  if (!selectedSource.value) return
  await perform(async () => {
    const { response } = await api.getResponse<Source>(`/api/v1/sources/${selectedSource.value!.id}`)
    await api.request<void>(`/api/v1/sources/${selectedSource.value!.id}`, { method: 'DELETE', headers: { 'If-Match': response.headers.get('ETag') || '' } })
    modal.value = null
    selectedSource.value = null
    await loadAll()
  }, '订阅已归档')
}

function openCollectionCreate() { editingID.value = ''; collectionForm.display_name = ''; collectionForm.source_ids = []; modal.value = 'collection' }
function openCollectionEdit(item: ManagedResource) {
  editingID.value = item.id
  editingETag.value = `"managed-resource-${item.id}-${item.revision_number}"`
  collectionForm.display_name = item.display_name
  collectionForm.source_ids = Array.isArray(item.configuration.members) ? item.configuration.members.filter(member => (member as { enabled?: boolean }).enabled !== false).map(member => (member as { id: string }).id) : []
  modal.value = 'collection'
}
async function saveCollection() {
  await perform(async () => {
    const payload = { display_name: collectionForm.display_name, members: collectionForm.source_ids.map(id => ({ kind: 'source', id, enabled: true })) }
    if (editingID.value) await api.put(`/api/v1/collections/${editingID.value}`, payload, editingETag.value)
    else await api.post('/api/v1/collections', payload)
    modal.value = null
    await loadAll()
  }, editingID.value ? '聚合已更新' : '聚合已创建')
}

function openPipelineCreate() { editingID.value = ''; pipelineForm.display_name = ''; pipelineForm.operations = '[]'; modal.value = 'pipeline' }
function openPipelineEdit(item: ManagedResource) {
  editingID.value = item.id
  editingETag.value = `"managed-resource-${item.id}-${item.revision_number}"`
  pipelineForm.display_name = item.display_name
  pipelineForm.operations = JSON.stringify(item.configuration.operations || [], null, 2)
  modal.value = 'pipeline'
}
function usePipelinePreset(kind: 'sort' | 'rename' | 'filter') {
  const presets = {
    sort: [{ type: 'sort', schema_version: 1, config: { by: 'name', descending: false } }],
    rename: [{ type: 'rename', schema_version: 1, config: { prefix: '', suffix: '', pattern: '旧名称', replacement: '新名称' } }],
    filter: [{ type: 'filter', schema_version: 1, config: { field: 'name', operator: 'regex', value: '(?i)剩余流量|到期' } }],
  }
  pipelineForm.operations = JSON.stringify(presets[kind], null, 2)
}
async function savePipeline() {
  await perform(async () => {
    const payload = { display_name: pipelineForm.display_name, operations: JSON.parse(pipelineForm.operations) }
    if (editingID.value) await api.put(`/api/v1/pipelines/${editingID.value}`, payload, editingETag.value)
    else await api.post('/api/v1/pipelines', payload)
    modal.value = null
    await loadAll()
  }, editingID.value ? '处理脚本已更新' : '处理脚本已创建')
}

async function createTemplate() {
  await perform(async () => {
    const payload: Record<string, unknown> = { display_name: templateForm.display_name, source_type: templateForm.source_type, target_format: 'sing-box' }
    if (templateForm.source_type === 'remote') {
      payload.url = templateForm.url
      payload.refresh_interval_seconds = templateForm.refresh_interval_seconds
      payload.private_network_authorized = templateForm.private_network_authorized
      if (templateForm.headers.trim()) {
        const headers = JSON.parse(templateForm.headers)
        if (!headers || Array.isArray(headers) || typeof headers !== 'object') throw new Error('请求头必须是 JSON 对象')
        payload.headers = headers
      }
    } else payload.content = templateForm.content
    await api.post('/api/v1/templates', payload)
    modal.value = null
    resetTemplateForm()
    await loadAll()
  }, '规则模板已添加')
}
async function refreshTemplate(template: ManagedResource) {
  await perform(async () => {
    const result = await api.post<{ changed: boolean }>(`/api/v1/templates/${template.id}/refresh`)
    await loadAll()
    toast.value = result.changed ? `${template.display_name} 已更新，相关输出正在重建` : `${template.display_name} 已是最新版本`
  })
}

async function createOutput() {
  await perform(async () => {
    const result = await api.post<{ subscription_url: string }>('/api/v1/outputs', {
      ...outputForm, pipeline_id: outputForm.pipeline_id || undefined,
      template_id: outputForm.output_shape === 'full_config' ? outputForm.template_id : undefined,
    })
    secretPath.value = result.subscription_url
    modal.value = null
    await loadAll()
  })
}
function openOutputPolicy(output: OutputItem) {
  selectedOutput.value = output
  outputForm.health_filter_enabled = output.health_filter_enabled
  outputForm.minimum_nodes = output.minimum_nodes
  outputForm.maximum_drop_ratio = output.maximum_drop_ratio
  modal.value = 'output-policy'
}
async function updateOutputPolicy() {
  if (!selectedOutput.value) return
  await perform(async () => {
    const result = await api.patch<{ job_id: string }>(`/api/v1/outputs/${selectedOutput.value!.id}`, {
      health_filter_enabled: outputForm.health_filter_enabled,
      minimum_nodes: outputForm.minimum_nodes,
      maximum_drop_ratio: outputForm.maximum_drop_ratio,
    })
    modal.value = null
    await pollJob(result.job_id, '输出策略更新')
    await loadAll()
  }, '输出策略已更新')
}
async function buildOutput(output: OutputItem) {
  await perform(async () => {
    const job = await api.post<{ id: string }>(`/api/v1/outputs/${output.id}/builds`)
    await pollJob(job.id, `${output.display_name} 构建`)
    await loadAll()
  })
}
async function rotateOutputToken(output: OutputItem) {
  await perform(async () => {
    const result = await api.post<{ subscription_url: string }>(`/api/v1/outputs/${output.id}/tokens`, { revoke_existing: false })
    secretPath.value = result.subscription_url
  })
}

async function checkNode(item: NodeItem) {
  await perform(async () => {
    await api.post(`/api/v1/nodes/${item.id}/checks`)
    toast.value = `${item.original_name || item.id.slice(0, 8)} 已加入检查队列`
  })
}
function toggleNode(id: string) {
  const next = new Set(selectedNodeIDs.value)
  next.has(id) ? next.delete(id) : next.add(id)
  selectedNodeIDs.value = next
}
function toggleVisibleNodes() {
  const visible = filteredNodes.value.map(item => item.id)
  const allSelected = visible.length > 0 && visible.every(id => selectedNodeIDs.value.has(id))
  const next = new Set(selectedNodeIDs.value)
  for (const id of visible) allSelected ? next.delete(id) : next.add(id)
  selectedNodeIDs.value = next
}
async function checkSelectedNodes() {
  const ids = [...selectedNodeIDs.value]
  if (!ids.length) return
  await perform(async () => {
    for (let start = 0; start < ids.length; start += 200) await api.post('/api/v1/node-checks', { node_occurrence_ids: ids.slice(start, start + 200) })
    selectedNodeIDs.value = new Set()
  }, `${ids.length} 个节点已加入检查队列`)
}
async function openNodeDetails(item: NodeItem) {
  await perform(async () => {
    selectedNode.value = item
    const page = await api.get<Page<HealthRecord>>(`/api/v1/nodes/${item.id}/health-records?limit=20`)
    healthRecords.value = page.items
    modal.value = 'node'
  })
}

async function changePassword() {
  if (passwordForm.new_password !== passwordForm.confirm_password) { error.value = '两次输入的新密码不一致'; return }
  await perform(async () => {
    await api.post<void>('/api/v1/session/password', { current_password: passwordForm.current_password, new_password: passwordForm.new_password })
    passwordForm.current_password = ''
    passwordForm.new_password = ''
    passwordForm.confirm_password = ''
    session.value = null
    api.csrf = ''
    authNotice.value = '密码已修改，请使用新密码登录。'
  })
}

async function pollJob(id: string, label: string): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt++) {
    const job = await api.get<{ status: string; error_detail?: string }>(`/api/v1/jobs/${id}`)
    if (job.status === 'succeeded') { toast.value = `${label}完成`; return }
    if (['failed', 'dead', 'cancelled'].includes(job.status)) throw new Error(job.error_detail || `${label}任务 ${job.status}`)
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  toast.value = `${label}仍在后台运行`
}

async function copySecret() {
  await navigator.clipboard.writeText(secretFullURL.value)
  toast.value = '订阅地址已复制'
}

function resetSourceForm() {
	sourceForm.display_name = ''; sourceForm.type = 'remote'; sourceForm.url = ''; sourceForm.headers = ''; sourceForm.proxy_url = ''
	sourceForm.clear_proxy = false; sourceForm.proxy_configured = false; sourceForm.masked_proxy = ''; sourceForm.content = ''
	sourceForm.input_format = 'auto'; sourceForm.timeout_seconds = 30; sourceForm.refresh_interval_seconds = 3600
  sourceForm.private_network_authorized = false; sourceForm.health_filter_enabled = false
}
function resetTemplateForm() {
  templateForm.display_name = ''; templateForm.source_type = 'remote'; templateForm.url = ''; templateForm.headers = ''
  templateForm.refresh_interval_seconds = 3600; templateForm.private_network_authorized = false; templateForm.content = defaultTemplateContent
}
function resetOutputForm() {
  outputForm.display_name = ''; outputForm.collection_id = ''; outputForm.pipeline_id = ''; outputForm.template_id = ''
  outputForm.target_profile = 'momo-1.2.1-sing-box-1.12.25'; outputForm.output_shape = 'full_config'
  outputForm.health_filter_enabled = true; outputForm.minimum_nodes = 1; outputForm.maximum_drop_ratio = 0.5
}

async function perform(work: () => Promise<void>, success = '') {
  loading.value = true
  error.value = ''
  try { await work(); if (success) toast.value = success } catch (cause) { showError(cause) } finally { loading.value = false }
}
function showError(cause: unknown) {
  if (cause instanceof ApiError) {
    const messages: Record<string, string> = {
      invalid_setup_token: '初始化令牌无效或已过期。请在 NAS 上重新执行页面中的命令，使用新令牌注册。',
      setup_already_complete: '管理员已经创建完成，请刷新页面后直接登录。',
      administrator_setup_failed: '管理员创建失败，请检查用户名、密码和时区后重试。',
      invalid_credentials: '用户名或密码不正确。',
      rate_limited: '尝试次数过多，请等待 5 分钟后再试。',
      storage_unavailable: '初始化存储暂时不可用，请检查容器状态。',
    }
    error.value = messages[cause.code] || cause.message
    return
  }
  error.value = cause instanceof Error ? cause.message : '请求失败'
}

onMounted(initialize)
</script>

<template>
  <div v-if="!setupChecked" class="center-state"><RefreshCw class="spin" :size="22" /></div>

  <main v-else-if="!session" class="auth-shell">
    <section class="auth-panel" :class="{ 'setup-panel': !initialized }">
      <div class="brand-mark"><Layers3 :size="25" /><span>ProxyLoom</span></div>
      <h1>{{ initialized ? '管理员登录' : '创建首个管理员' }}</h1>
      <p class="auth-subtitle">{{ initialized ? '登录后管理订阅、节点健康与输出配置。' : '使用 NAS 本机生成的一次性令牌完成安全初始化。' }}</p>
      <p v-if="authNotice" class="auth-notice">{{ authNotice }}</p>
      <form @submit.prevent="initialized ? login() : setupAdministrator()">
        <template v-if="!initialized">
          <div class="setup-guide">
            <ShieldCheck :size="20" />
            <div><strong>先在 NAS 上生成初始化令牌</strong><p>通过 SSH 或终端进入 ProxyLoom 的 Compose 目录，执行下面的命令。令牌 24 小时内有效且只能使用一次。</p></div>
            <div class="setup-command"><code>{{ setupCommand }}</code><button type="button" class="icon-button" title="复制命令" @click="copySetupCommand"><Clipboard :size="16" /></button></div>
          </div>
          <label>初始化令牌<input v-model.trim="auth.setupToken" required type="password" autocomplete="off" placeholder="plst1_..." /><small>粘贴命令输出中以 plst1_ 开头的完整内容。</small></label>
          <div class="form-row">
            <label>管理员用户名<input v-model.trim="auth.username" required autocomplete="username" minlength="3" maxlength="64" /><small>3–64 字节，默认使用 admin 即可。</small></label>
            <label>密码<input v-model="auth.password" required :type="auth.showPassword ? 'text' : 'password'" autocomplete="new-password" maxlength="1024" /><small>不能为空，不再要求至少 12 个字符。</small></label>
          </div>
          <label>确认密码<input v-model="auth.confirmPassword" required :type="auth.showPassword ? 'text' : 'password'" autocomplete="new-password" maxlength="1024" /></label>
          <label class="check"><input v-model="auth.showPassword" type="checkbox" />显示密码</label>
          <details class="setup-advanced"><summary>高级设置</summary><label>时区<input v-model.trim="auth.timezone" required maxlength="64" /></label></details>
        </template>
        <template v-else>
          <label>用户名<input v-model.trim="auth.username" required autocomplete="username" maxlength="64" /></label>
          <label>密码<input v-model="auth.password" required :type="auth.showPassword ? 'text' : 'password'" autocomplete="current-password" maxlength="1024" /></label>
          <label class="check"><input v-model="auth.showPassword" type="checkbox" />显示密码</label>
        </template>
        <p v-if="error" class="form-error">{{ error }}</p>
        <button class="primary wide" :disabled="loading"><KeyRound :size="17" />{{ initialized ? '登录' : '创建管理员并登录' }}</button>
      </form>
    </section>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand-mark compact"><Layers3 :size="22" /><span>ProxyLoom</span></div>
      <nav>
        <button v-for="item in navigation" :key="item.id" :class="{ active: active === item.id }" :aria-label="item.label" :title="item.label" @click="switchView(item.id)">
          <component :is="item.icon" :size="18" /><span>{{ item.label }}</span>
        </button>
      </nav>
      <div class="sidebar-user">
        <div><span>{{ session.administrator.username }}</span><small>管理员</small></div>
        <button class="icon-button inverse" title="退出登录" @click="logout"><LogOut :size="17" /></button>
      </div>
    </aside>

    <main class="workspace">
      <header class="topbar">
        <div><h1>{{ pageTitle }}</h1><span v-if="activeCount !== ''" class="count">{{ activeCount }}</span></div>
        <div class="toolbar">
          <label v-if="['sources', 'nodes', 'rules', 'outputs'].includes(active)" class="search"><Search :size="16" /><input v-model="query" aria-label="搜索" placeholder="搜索" /></label>
          <button class="icon-button" title="刷新数据" :disabled="loading" @click="refreshData"><RefreshCw :size="17" :class="{ spin: loading }" /></button>
          <button v-if="addLabel" class="primary" @click="openCreate"><Plus :size="17" />{{ addLabel }}</button>
        </div>
      </header>

      <div v-if="error" class="alert"><span>{{ error }}</span><button class="icon-button" title="关闭" @click="error = ''"><X :size="16" /></button></div>
      <div v-if="toast" class="toast" @click="toast = ''"><CheckCircle2 :size="17" />{{ toast }}</div>

      <section v-if="active === 'overview'" class="overview">
        <div class="summary-strip">
          <div><span>订阅源</span><strong>{{ sources.length }}</strong><small>{{ sourceIssues.length ? `${sourceIssues.length} 个需要关注` : '全部正常刷新' }}</small></div>
          <div><span>可用节点</span><strong>{{ availableNodes }}</strong><small>共导入 {{ nodes.length }} 个</small></div>
          <div><span>健康节点</span><strong>{{ healthRate }}%</strong><small>{{ healthyNodes }} 个已通过检查</small></div>
          <div><span>输出订阅</span><strong>{{ outputs.length }}</strong><small>{{ outputs.filter(item => item.current_artifact_id).length }} 个已有产物</small></div>
        </div>

        <div class="overview-columns">
          <section class="section-block">
            <header><div><h2>需要处理</h2><p>订阅与节点的当前异常</p></div><button @click="switchView('nodes')">查看健康详情<ChevronRight :size="16" /></button></header>
            <div class="attention-list">
              <button v-for="item in sourceIssues.slice(0, 5)" :key="item.id" @click="switchView('sources')"><span :class="statusClass(item.health, item.stale)">{{ healthLabel(item.health, item.stale) }}</span><strong>{{ item.display_name }}</strong><small>{{ sourceNodeCount(item.id) }} 个节点</small><ChevronRight :size="16" /></button>
              <div v-if="!sourceIssues.length && !unhealthyNodes" class="empty compact"><CheckCircle2 :size="24" /><span>当前没有需要处理的异常</span></div>
              <button v-if="unhealthyNodes" @click="healthFilter = 'unhealthy'; switchView('nodes')"><span class="status unhealthy">不可用</span><strong>{{ unhealthyNodes }} 个节点检查失败</strong><small>可批量重新检查</small><ChevronRight :size="16" /></button>
              <button v-if="uncheckedNodes" @click="healthFilter = 'unchecked'; switchView('nodes')"><span class="status neutral">待检查</span><strong>{{ uncheckedNodes }} 个节点等待结论</strong><small>可手动加入检查队列</small><ChevronRight :size="16" /></button>
            </div>
          </section>

          <section class="section-block quick-actions">
            <header><div><h2>常用操作</h2><p>从导入到输出的主要入口</p></div></header>
            <button @click="openSourceCreate"><Plus :size="18" /><span><strong>添加订阅链接</strong><small>导入远程订阅或原始节点</small></span><ChevronRight :size="16" /></button>
            <button @click="ruleTab = 'collections'; switchView('rules')"><Layers3 :size="18" /><span><strong>调整聚合范围</strong><small>选择输出中包含的订阅源</small></span><ChevronRight :size="16" /></button>
            <button @click="switchView('outputs')"><Send :size="18" /><span><strong>构建输出订阅</strong><small>生成客户端可直接使用的地址</small></span><ChevronRight :size="16" /></button>
            <button @click="switchView('guide')"><BookOpen :size="18" /><span><strong>查看使用说明</strong><small>第一次使用建议从这里开始</small></span><ChevronRight :size="16" /></button>
          </section>
        </div>

        <section class="section-block recent-block">
          <header><div><h2>最近订阅</h2><p>节点数量与刷新状态</p></div><button @click="switchView('sources')">管理全部<ChevronRight :size="16" /></button></header>
          <div class="compact-table"><div v-for="item in sources.slice(0, 6)" :key="item.id"><strong>{{ item.display_name }}</strong><span>{{ sourceNodeCount(item.id) }} 个节点</span><span :class="statusClass(item.health, item.stale)">{{ healthLabel(item.health, item.stale) }}</span><time>{{ formatDate(item.updated_at) }}</time></div></div>
        </section>
      </section>

      <section v-else-if="active === 'sources'" class="table-wrap">
        <table><thead><tr><th>订阅名称</th><th>节点</th><th>刷新策略</th><th>状态</th><th>最近更新</th><th></th></tr></thead>
          <tbody><tr v-for="item in filteredSources" :key="item.id">
            <td><div class="primary-cell"><strong>{{ item.display_name }}</strong><small class="mono">{{ item.masked_location || '内联内容' }}</small></div></td>
            <td>{{ sourceNodeCount(item.id) }}</td>
            <td>{{ formatInterval(item.configuration?.refresh_interval_seconds || 0) }}</td>
            <td><span :class="statusClass(item.health, item.stale)">{{ healthLabel(item.health, item.stale) }}</span></td>
            <td>{{ formatDate(item.updated_at) }}</td>
            <td class="actions">
              <button class="icon-button" title="立即刷新" :disabled="loading" @click="refreshSource(item)"><RefreshCw :size="16" /></button>
              <button class="icon-button" title="编辑订阅" @click="openSourceEdit(item)"><Pencil :size="16" /></button>
              <button class="icon-button" title="生成订阅地址" @click="createSourceToken(item)"><KeyRound :size="16" /></button>
              <button class="icon-button danger-icon" title="归档订阅" @click="selectedSource = item; modal = 'archive-source'"><Trash2 :size="16" /></button>
            </td>
          </tr></tbody>
        </table><div v-if="!filteredSources.length" class="empty"><Database :size="28" /><span>没有匹配的订阅</span><button class="primary" @click="openSourceCreate"><Plus :size="16" />添加订阅</button></div>
      </section>

      <template v-else-if="active === 'nodes'">
        <section class="health-summary">
          <button v-for="item in [{id:'all',label:'全部'}, {id:'healthy',label:'健康'}, {id:'degraded',label:'不稳定'}, {id:'unhealthy',label:'不可用'}, {id:'unchecked',label:'待检查'}, {id:'unsupported',label:'客户端检查'}]" :key="item.id" :class="{ active: healthFilter === item.id }" @click="healthFilter = item.id">
            <span>{{ item.label }}</span><strong>{{ healthCounts[item.id] || 0 }}</strong>
          </button>
        </section>
        <section class="filterbar">
          <select v-model="sourceFilter" aria-label="按订阅筛选"><option value="all">全部订阅</option><option v-for="item in sources" :key="item.id" :value="item.id">{{ item.display_name }}</option></select>
          <select v-model="protocolFilter" aria-label="按协议筛选"><option value="all">全部协议</option><option v-for="protocol in sourceProtocols" :key="protocol" :value="protocol">{{ protocol }}</option></select>
          <span>{{ filteredNodes.length }} 个结果</span>
          <button class="primary" :disabled="!selectedNodeIDs.size || loading" @click="checkSelectedNodes"><ListChecks :size="16" />复测已选（{{ selectedNodeIDs.size }}）</button>
        </section>
        <section class="table-wrap node-table">
          <table><thead><tr><th><input type="checkbox" aria-label="选择当前结果" :checked="filteredNodes.length > 0 && filteredNodes.every(item => selectedNodeIDs.has(item.id))" @change="toggleVisibleNodes" /></th><th>节点</th><th>订阅</th><th>协议</th><th>健康状态</th><th>状态更新</th><th></th></tr></thead>
            <tbody><tr v-for="item in filteredNodes" :key="item.id"><td><input type="checkbox" :aria-label="`选择 ${item.original_name}`" :checked="selectedNodeIDs.has(item.id)" @change="toggleNode(item.id)" /></td><td class="strong">{{ item.original_name || item.id.slice(0, 8) }}</td><td>{{ sourceName(item.source_id) }}</td><td class="mono">{{ item.protocol }}</td><td><span :class="statusClass(item.health, item.stale)">{{ healthLabel(item.health, item.stale) }}</span></td><td>{{ formatDate(item.health_updated_at) }}</td><td class="actions"><button class="icon-button" title="查看检查记录" @click="openNodeDetails(item)"><Eye :size="16" /></button><button class="icon-button" title="立即复测" :disabled="loading" @click="checkNode(item)"><RefreshCw :size="16" /></button></td></tr></tbody>
          </table><div v-if="!filteredNodes.length" class="empty"><Network :size="28" /><span>没有匹配的节点</span></div>
        </section>
      </template>

      <template v-else-if="active === 'rules'">
        <div class="tabs">
          <button :class="{ active: ruleTab === 'collections' }" @click="ruleTab = 'collections'; query = ''">聚合范围</button>
          <button :class="{ active: ruleTab === 'templates' }" @click="ruleTab = 'templates'; query = ''">规则模板</button>
          <button :class="{ active: ruleTab === 'pipelines' }" @click="ruleTab = 'pipelines'; query = ''">节点处理脚本</button>
        </div>
        <div class="context-note">
          <Layers3 v-if="ruleTab === 'collections'" :size="18" /><FileJson2 v-else-if="ruleTab === 'templates'" :size="18" /><SlidersHorizontal v-else :size="18" />
          <span v-if="ruleTab === 'collections'">聚合范围决定一次输出使用哪些订阅源。</span>
          <span v-else-if="ruleTab === 'templates'">规则模板从 GitHub 等远程地址定时拉取，并与节点合成为完整配置。</span>
          <span v-else>处理脚本在输出前按顺序过滤、改名或排序节点。</span>
        </div>
        <section v-if="ruleTab === 'collections'" class="resource-list">
          <article v-for="item in filteredCollections" :key="item.id"><Layers3 :size="20" /><div class="resource-main"><h2>{{ item.display_name }}</h2><span>{{ memberCount(item) }} 个订阅源</span></div><span class="revision">版本 {{ item.revision_number }}</span><time>{{ formatDate(item.updated_at) }}</time><button class="icon-button" title="编辑聚合范围" @click="openCollectionEdit(item)"><Pencil :size="16" /></button></article>
          <div v-if="!filteredCollections.length" class="empty"><Layers3 :size="28" /><span>还没有聚合范围</span></div>
        </section>
        <section v-else-if="ruleTab === 'templates'" class="resource-list">
          <article v-for="item in filteredTemplates" :key="item.id"><FileJson2 :size="20" /><div class="resource-main"><h2>{{ item.display_name }}</h2><span>{{ templateSummary(item) }}</span></div><span class="revision">版本 {{ item.revision_number }}</span><time>{{ formatDate(item.updated_at) }}</time><button v-if="isRemoteTemplate(item)" class="icon-button" title="立即拉取模板" :disabled="loading" @click="refreshTemplate(item)"><RefreshCw :size="16" /></button></article>
          <div v-if="!filteredTemplates.length" class="empty"><FileJson2 :size="28" /><span>还没有规则模板</span></div>
        </section>
        <section v-else class="resource-list">
          <article v-for="item in filteredPipelines" :key="item.id"><SlidersHorizontal :size="20" /><div class="resource-main"><h2>{{ item.display_name }}</h2><span>{{ operationCount(item) ? `${operationCount(item)} 个处理步骤` : '不修改节点，保持原样' }}</span></div><span class="revision">版本 {{ item.revision_number }}</span><time>{{ formatDate(item.updated_at) }}</time><button class="icon-button" title="编辑处理脚本" @click="openPipelineEdit(item)"><Pencil :size="16" /></button></article>
          <div v-if="!filteredPipelines.length" class="empty"><SlidersHorizontal :size="28" /><span>还没有节点处理脚本</span></div>
        </section>
      </template>

      <section v-else-if="active === 'outputs'" class="output-list">
        <article v-for="item in filteredOutputs" :key="item.id">
          <div class="output-status"><Send :size="20" /><span :class="statusClass(item.current_artifact_id ? 'ready' : 'unchecked')">{{ item.current_artifact_id ? '可订阅' : '待构建' }}</span></div>
          <div class="output-main"><h2>{{ item.display_name }}</h2><p>{{ collectionName(item.collection_id) }} · {{ templateName(item.template_id) }}</p><div><span>{{ outputProfile(item.target_profile) }}</span><span>{{ item.health_filter_enabled ? '过滤不可用节点' : '保留全部节点' }}</span><span>至少保留 {{ item.minimum_nodes }} 个</span></div></div>
          <div class="output-actions"><button title="修改输出策略" @click="openOutputPolicy(item)"><Settings :size="16" />策略</button><button title="立即构建" :disabled="loading" @click="buildOutput(item)"><Play :size="16" />构建</button><button class="primary" title="生成新的订阅地址" @click="rotateOutputToken(item)"><KeyRound :size="16" />获取地址</button></div>
        </article>
        <div v-if="!filteredOutputs.length" class="empty"><Boxes :size="28" /><span>还没有输出订阅</span><button class="primary" @click="resetOutputForm(); modal = 'output'"><Plus :size="16" />新建输出</button></div>
      </section>

      <section v-else-if="active === 'settings'" class="settings-layout">
        <section class="settings-section">
          <header><KeyRound :size="20" /><div><h2>登录密码</h2><p>修改后所有设备需要重新登录</p></div></header>
          <form class="settings-form" @submit.prevent="changePassword">
            <label>当前密码<input v-model="passwordForm.current_password" required type="password" autocomplete="current-password" maxlength="1024" /></label>
            <label>新密码<input v-model="passwordForm.new_password" required type="password" autocomplete="new-password" maxlength="1024" /></label>
            <label>确认新密码<input v-model="passwordForm.confirm_password" required type="password" autocomplete="new-password" maxlength="1024" /></label>
            <button class="primary" :disabled="loading"><Save :size="16" />修改密码</button>
          </form>
        </section>
        <section class="settings-section">
          <header><Gauge :size="20" /><div><h2>健康检查运行状态</h2><p>用于判断后台检查是否正常工作</p></div></header>
          <div class="system-grid">
            <div><span>等待检查</span><strong>{{ capacity?.queued ?? 0 }}</strong></div><div><span>正在检查</span><strong>{{ capacity?.running ?? 0 }}</strong></div><div><span>检查并发</span><strong>{{ capacity?.configured_concurrency ?? 0 }}</strong></div><div><span>过滤保护</span><strong>{{ capacity?.filter_suppressed ? '已触发' : '正常' }}</strong></div>
          </div>
          <p class="system-footnote"><ShieldCheck :size="16" />{{ capacity?.guard_conclusion || '暂无异常结论' }}</p>
        </section>
      </section>

      <article v-else class="guide">
        <section class="guide-intro"><BookOpen :size="24" /><div><h2>从订阅链接到客户端配置</h2><p>按照下面的顺序完成一次配置，后续刷新与健康过滤会自动运行。</p></div></section>
        <ol class="guide-steps">
          <li><span>1</span><div><h3>添加订阅</h3><p>进入“订阅管理”，添加机场订阅 URL、单个节点 URI，或直接粘贴 sing-box / Mihomo 原始内容。输入格式通常保持“自动识别”。</p><button @click="switchView('sources')">打开订阅管理<ChevronRight :size="16" /></button></div></li>
          <li><span>2</span><div><h3>选择聚合范围</h3><p>在“聚合与规则”中建立聚合范围并勾选需要合并的订阅。需要从 GitHub 拉取完整 sing-box 规则时，再添加远程规则模板。</p><button @click="ruleTab = 'collections'; switchView('rules')">打开聚合与规则<ChevronRight :size="16" /></button></div></li>
          <li><span>3</span><div><h3>按需处理节点</h3><p>节点处理脚本是可选项。它可以过滤流量提示节点、批量替换名称或调整排序；不选择脚本时，ProxyLoom 会保留原节点内容并自动处理重名。</p><button @click="ruleTab = 'pipelines'; switchView('rules')">查看处理脚本<ChevronRight :size="16" /></button></div></li>
		  <li><span>4</span><div><h3>创建输出</h3><p>选择聚合范围、规则模板和目标客户端。启用健康过滤后，已确认不可用的节点不会进入新产物；ECH 节点由兼容的 sing-box 1.13 执行器检查。</p><button @click="switchView('outputs')">打开输出订阅<ChevronRight :size="16" /></button></div></li>
          <li><span>5</span><div><h3>复制地址并加入客户端</h3><p>点击输出右侧“获取地址”，复制一次性展示的订阅 URL。地址包含访问凭据，不要公开；需要废弃旧地址时可在后续版本中轮换并撤销。</p></div></li>
        </ol>
		<section class="guide-reference"><h3>常见状态</h3><dl><div><dt><span class="status healthy">健康</span></dt><dd>节点已经通过最近一次主动检查。</dd></div><div><dt><span class="status unhealthy">不可用</span></dt><dd>连续失败达到阈值，会从启用健康过滤的输出中排除。</dd></div><div><dt><span class="status neutral">客户端检查</span></dt><dd>当前容器没有相应协议或版本的兼容执行器，节点会保留给客户端检查。</dd></div><div><dt><span class="status stale">已过期</span></dt><dd>检查结论或订阅快照已经过期，需要刷新或重新检查。</dd></div></dl></section>
      </article>
    </main>
  </div>

  <div v-if="modal" class="modal-backdrop" @mousedown.self="modal = null">
    <section class="modal" :class="{ 'wide-modal': modal === 'node' || modal === 'pipeline' }" role="dialog" aria-modal="true">
      <header>
        <h2>{{ modal === 'source' ? (editingID ? '编辑订阅' : '添加订阅') : modal === 'collection' ? (editingID ? '编辑聚合范围' : '新建聚合范围') : modal === 'pipeline' ? (editingID ? '编辑节点处理脚本' : '新建节点处理脚本') : modal === 'template' ? '添加规则模板' : modal === 'output' ? '新建输出订阅' : modal === 'output-policy' ? '输出策略' : modal === 'node' ? '节点检查记录' : '归档订阅' }}</h2>
        <button class="icon-button" title="关闭" @click="modal = null"><X :size="18" /></button>
      </header>

      <form v-if="modal === 'source'" @submit.prevent="saveSource">
        <label>名称<input v-model.trim="sourceForm.display_name" required maxlength="200" /></label>
        <div v-if="!editingID" class="segmented"><button type="button" :class="{ active: sourceForm.type === 'remote' }" @click="sourceForm.type = 'remote'">远程订阅</button><button type="button" :class="{ active: sourceForm.type === 'inline' }" @click="sourceForm.type = 'inline'">粘贴原始内容</button></div>
        <label v-if="sourceForm.type === 'remote'">{{ editingID ? '新的订阅 URL（留空则保持原地址）' : '订阅 URL' }}<input v-model.trim="sourceForm.url" :required="!editingID" type="url" autocomplete="off" /></label>
        <label v-else>{{ editingID ? '新的原始内容（留空则保持原内容）' : '原始内容' }}<textarea v-model="sourceForm.content" :required="!editingID" rows="9" spellcheck="false"></textarea></label>
		<label v-if="sourceForm.type === 'remote'">{{ editingID ? '新的请求头 JSON（留空则保持现有请求头）' : '请求头 JSON（可选）' }}<textarea v-model="sourceForm.headers" rows="3" spellcheck="false" placeholder='{"Authorization":"Bearer ...","User-Agent":"sing-box"}'></textarea></label>
		<label v-if="sourceForm.type === 'remote'">{{ editingID ? '新的拉取代理（留空则保持现有代理）' : '拉取代理（可选）' }}<input v-model.trim="sourceForm.proxy_url" type="url" autocomplete="off" placeholder="socks5h://192.0.2.10:1080" /><small v-if="editingID && sourceForm.proxy_configured">当前代理：{{ sourceForm.masked_proxy }}</small></label>
		<label v-if="editingID && sourceForm.type === 'remote' && sourceForm.proxy_configured" class="check"><input v-model="sourceForm.clear_proxy" type="checkbox" :disabled="!!sourceForm.proxy_url" />清除当前代理</label>
		<div class="form-row"><label>输入格式<select v-model="sourceForm.input_format"><option value="auto">自动识别</option><option value="sing-box">sing-box</option><option value="mihomo">Mihomo</option><option value="client-text">Surge / Loon / QX</option><option value="uri-list">URI / Base64</option></select></label><label v-if="sourceForm.type === 'remote'">自动刷新<select v-model.number="sourceForm.refresh_interval_seconds"><option :value="0">仅手动</option><option :value="60">每 1 分钟</option><option :value="300">每 5 分钟</option><option :value="900">每 15 分钟</option><option :value="3600">每 1 小时</option><option :value="21600">每 6 小时</option><option :value="86400">每天</option></select></label></div>
		<label v-if="sourceForm.type === 'remote'">拉取超时（秒）<input v-model.number="sourceForm.timeout_seconds" type="number" min="1" max="120" required /></label>
        <label v-if="sourceForm.type === 'remote'" class="check"><input v-model="sourceForm.private_network_authorized" type="checkbox" />允许这个订阅访问私网地址</label>
        <label class="check"><input v-model="sourceForm.health_filter_enabled" type="checkbox" />单独输出该订阅时过滤不可用节点</label>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading"><Save v-if="editingID" :size="17" /><Plus v-else :size="17" />{{ editingID ? '保存并刷新' : '添加并刷新' }}</button></footer>
      </form>

      <form v-else-if="modal === 'collection'" @submit.prevent="saveCollection">
        <label>名称<input v-model.trim="collectionForm.display_name" required maxlength="200" /></label>
        <fieldset><legend>包含的订阅</legend><label v-for="item in sources" :key="item.id" class="check source-choice"><input v-model="collectionForm.source_ids" type="checkbox" :value="item.id" /><span>{{ item.display_name }}</span><small>{{ sourceNodeCount(item.id) }} 个节点</small></label></fieldset>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading || !collectionForm.source_ids.length"><Save :size="17" />保存</button></footer>
      </form>

      <form v-else-if="modal === 'pipeline'" @submit.prevent="savePipeline">
        <label>名称<input v-model.trim="pipelineForm.display_name" required maxlength="200" /></label>
        <div class="preset-row"><span>从示例开始</span><button type="button" @click="usePipelinePreset('filter')">过滤提示节点</button><button type="button" @click="usePipelinePreset('rename')">替换名称</button><button type="button" @click="usePipelinePreset('sort')">按名称排序</button></div>
        <label>处理步骤 JSON<textarea v-model="pipelineForm.operations" required rows="17" spellcheck="false"></textarea></label>
        <p class="field-help">步骤按数组顺序执行。支持 <code>filter</code>、<code>rename</code> 和 <code>sort</code>；保存时会验证格式。</p>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading"><Save :size="17" />保存</button></footer>
      </form>

      <form v-else-if="modal === 'template'" @submit.prevent="createTemplate">
        <label>名称<input v-model.trim="templateForm.display_name" required maxlength="200" /></label>
        <div class="segmented"><button type="button" :class="{ active: templateForm.source_type === 'remote' }" @click="templateForm.source_type = 'remote'">远程 URL</button><button type="button" :class="{ active: templateForm.source_type === 'inline' }" @click="templateForm.source_type = 'inline'">粘贴配置</button></div>
        <template v-if="templateForm.source_type === 'remote'"><label>模板 URL<input v-model.trim="templateForm.url" required type="url" autocomplete="off" /></label><label>自动刷新<select v-model.number="templateForm.refresh_interval_seconds"><option :value="300">每 5 分钟</option><option :value="900">每 15 分钟</option><option :value="3600">每 1 小时</option><option :value="21600">每 6 小时</option><option :value="86400">每天</option></select></label><label>请求头 JSON（可选）<textarea v-model="templateForm.headers" rows="4" spellcheck="false" placeholder='{"Authorization":"Bearer ..."}'></textarea></label><label class="check"><input v-model="templateForm.private_network_authorized" type="checkbox" />允许访问私网地址</label></template>
        <label v-else>sing-box 完整配置<textarea v-model="templateForm.content" required rows="17" spellcheck="false"></textarea></label>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading"><Plus :size="17" />添加模板</button></footer>
      </form>

      <form v-else-if="modal === 'output'" @submit.prevent="createOutput">
        <label>名称<input v-model.trim="outputForm.display_name" required maxlength="200" /></label>
        <div class="form-row"><label>聚合范围<select v-model="outputForm.collection_id" required><option value="" disabled>选择聚合范围</option><option v-for="item in collections" :key="item.id" :value="item.id">{{ item.display_name }}</option></select></label><label>节点处理脚本<select v-model="outputForm.pipeline_id"><option value="">不处理</option><option v-for="item in pipelines" :key="item.id" :value="item.id">{{ item.display_name }}</option></select></label></div>
        <div class="form-row"><label>输出内容<select v-model="outputForm.output_shape"><option value="full_config">完整客户端配置</option><option value="outbounds_object">仅 Outbounds 对象</option></select></label><label v-if="outputForm.output_shape === 'full_config'">规则模板<select v-model="outputForm.template_id" required><option value="" disabled>选择规则模板</option><option v-for="item in templates" :key="item.id" :value="item.id">{{ item.display_name }}</option></select></label></div>
        <label>目标客户端<select v-model="outputForm.target_profile"><option value="momo-1.2.1-sing-box-1.12.25">Momo 1.2.1 / sing-box 1.12.25</option><option value="sing-box-1.12.25">sing-box 1.12.25</option><option value="sing-box-1.13.14">sing-box 1.13.14</option></select></label>
        <div class="form-row"><label>至少保留节点数<input v-model.number="outputForm.minimum_nodes" type="number" min="1" max="100000" /></label><label>单次最多减少比例<input v-model.number="outputForm.maximum_drop_ratio" type="number" min="0" max="1" step="0.05" /></label></div>
        <label class="check"><input v-model="outputForm.health_filter_enabled" type="checkbox" />过滤已确认不可用节点</label>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading"><Plus :size="17" />创建输出</button></footer>
      </form>

      <form v-else-if="modal === 'output-policy'" @submit.prevent="updateOutputPolicy">
        <div class="context-note"><ShieldCheck :size="18" /><span>{{ selectedOutput?.display_name }}</span></div>
        <label class="check"><input v-model="outputForm.health_filter_enabled" type="checkbox" />构建时排除已确认不可用节点</label>
        <div class="form-row"><label>至少保留节点数<input v-model.number="outputForm.minimum_nodes" required type="number" min="1" max="100000" /></label><label>单次最多减少比例<input v-model.number="outputForm.maximum_drop_ratio" required type="number" min="0" max="1" step="0.05" /></label></div>
        <p class="field-help">保护阈值用于避免订阅或检查服务异常时一次性发布过少节点。保存后会自动构建新产物。</p>
        <footer><button type="button" @click="modal = null">取消</button><button class="primary" :disabled="loading"><Save :size="17" />保存并构建</button></footer>
      </form>

      <div v-else-if="modal === 'node'" class="node-detail">
        <div class="node-detail-head"><div><strong>{{ selectedNode?.original_name }}</strong><span>{{ selectedNode?.protocol }} · {{ selectedNode ? sourceName(selectedNode.source_id) : '' }}</span></div><span :class="statusClass(selectedNode?.health || '', selectedNode?.stale)">{{ healthLabel(selectedNode?.health || '', selectedNode?.stale) }}</span><button :disabled="loading || !selectedNode" @click="selectedNode && checkNode(selectedNode)"><RefreshCw :size="16" />立即复测</button></div>
		<div class="record-list"><div class="record-row record-header"><span>时间</span><span>结果</span><span>延迟</span><span>诊断 / 执行器</span></div><div v-for="record in healthRecords" :key="record.id" class="record-row"><time>{{ formatDate(record.observed_at) }}</time><span :class="statusClass(record.success ? 'healthy' : 'unhealthy')">{{ record.success ? '成功' : '失败' }}</span><span>{{ record.total_ms > 0 ? `${record.total_ms} ms` : '-' }}</span><code>{{ record.diagnostic_code || record.result_class }} · {{ record.executor_id }} {{ record.executor_version }}</code></div><div v-if="!healthRecords.length" class="empty compact">暂无检查记录</div></div>
      </div>

      <div v-else-if="modal === 'archive-source'" class="confirm-body">
        <Trash2 :size="24" /><h3>归档“{{ selectedSource?.display_name }}”吗？</h3><p>它将不再自动刷新，也不会进入后续构建。已有历史和产物会保留。</p><footer><button @click="modal = null">取消</button><button class="danger" :disabled="loading" @click="confirmArchiveSource"><Trash2 :size="16" />确认归档</button></footer>
      </div>
    </section>
  </div>

  <div v-if="secretPath" class="modal-backdrop" @mousedown.self="secretPath = ''">
    <section class="modal secret-modal" role="dialog" aria-modal="true">
      <header><h2>订阅地址</h2><button class="icon-button" title="关闭" @click="secretPath = ''"><X :size="18" /></button></header>
      <p class="secret-warning">该地址包含访问凭据，只会在这里展示一次。</p>
      <div class="secret-value"><code>{{ secretFullURL }}</code><button class="icon-button" title="复制订阅地址" @click="copySecret"><Clipboard :size="17" /></button></div>
      <footer><button class="primary" @click="secretPath = ''"><Check :size="16" />完成</button></footer>
    </section>
  </div>
</template>
