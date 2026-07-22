export interface Page<T> { items: T[]; page: { has_more: boolean; next_cursor: string | null } }

export interface Session {
  administrator: { id: string; username: string }
  csrf_token: string
  expires_at: string
  recent_auth_until: string
}

export interface Source {
  id: string
  display_name: string
  lifecycle_state: string
  health: string
  stale: boolean
  current_snapshot_id: string | null
	masked_location: string | null
	masked_proxy: string | null
	consecutive_failures: number
	last_refresh_error_code: string | null
	next_refresh_at: string | null
	next_retry_at: string | null
	retry_scheduled: boolean
  configuration?: {
    type: string
    input_format: string
    output_format: string
    minimum_nodes: number
    maximum_drop_ratio: number
		refresh_interval_seconds: number
		retry_count: number
		stale_after_seconds: number
		timeout_seconds: number
		proxy_configured: boolean
    private_network_authorized: boolean
    max_response_bytes: number
    health_filter_enabled: boolean
  }
  updated_at: string
}

export interface NodeItem {
  id: string
  source_id: string
  protocol: string
  original_name: string
  occurrence_state: string
  health: string
  stale: boolean
  last_seen_at: string
  health_updated_at: string
}

export interface HealthRecord {
  id: string
  result_class: string
  success: boolean
  total_ms: number
	diagnostic_code: string | null
	executor_id: string
	executor_version: string
	observed_at: string
  stale: boolean
}

export interface ManagedResource {
  id: string
  type: string
  display_name: string
  revision_number: number
  lifecycle_state: string
  configuration: Record<string, unknown>
  updated_at: string
}

export interface OutputItem {
  id: string
  display_name: string
  collection_id: string
  pipeline_id: string | null
  template_id: string | null
  target_profile: string
  output_shape: string
  health_filter_enabled: boolean
  minimum_nodes: number
  maximum_drop_ratio: number
  current_artifact_id: string | null
  next_build_sequence: number
  lifecycle_state: string
  updated_at: string
}

export interface Capacity {
  queue_total: number
  queued: number
  running: number
  dormant: number
  queue_hard_limit: number
  filter_suppressed: boolean
  guard_conclusion: string
  executor_concurrency: number
  configured_concurrency: number
}
