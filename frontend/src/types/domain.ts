export type Role = 'viewer' | 'analyst' | 'admin'

export type AssessmentStatus = 'draft' | 'authorized' | 'running' | 'completed' | 'cancelled' | 'failed'

export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'remediated'

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'

export type TargetType = 'ip_address' | 'hostname' | 'url' | 'network'
