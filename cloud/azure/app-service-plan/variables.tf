# Global

variable "environment" {
  description = "Infrastructure environment"
  type        = string
}

# SignalFx module specific

variable "notifications" {
  description = "Default notification recipients list per severity"
  type = object({
    critical = list(string)
    major    = list(string)
    minor    = list(string)
    warning  = list(string)
    info     = list(string)
  })
}

variable "prefixes" {
  description = "Prefixes list to prepend between brackets on every monitors names before environment"
  type        = list(string)
  default     = []
}

variable "filter_custom_includes" {
  description = "List of tags to include when custom filtering is used"
  type        = list(string)
  default     = []
}

variable "filter_custom_excludes" {
  description = "List of tags to exclude when custom filtering is used"
  type        = list(string)
  default     = []
}

variable "detectors_disabled" {
  description = "Disable all detectors in this module"
  type        = bool
  default     = false
}

# Azure serverfarms detectors specific

variable "heartbeat_disabled" {
  description = "Disable all alerting rules for heartbeat detector"
  type        = bool
  default     = null
}

variable "heartbeat_notifications" {
  description = "Notification recipients list per severity overridden for heartbeat detector"
  type        = map(list(string))
  default     = {}
}

variable "heartbeat_timeframe" {
  description = "Timeframe for heartbeat detector (i.e. \"10m\")"
  type        = string
  default     = "20m"
}

# CPU_percentage detectors

variable "cpu_percentage_disabled" {
  description = "Disable all alerting rules for cpu_percentage detector"
  type        = bool
  default     = null
}

variable "cpu_percentage_disabled_critical" {
  description = "Disable critical alerting rule for cpu_percentage detector"
  type        = bool
  default     = null
}

variable "cpu_percentage_disabled_major" {
  description = "Disable major alerting rule for cpu_percentage detector"
  type        = bool
  default     = null
}

variable "cpu_percentage_notifications" {
  description = "Notification recipients list per severity overridden for cpu_percentage detector"
  type        = map(list(string))
  default     = {}
}

variable "cpu_percentage_aggregation_function" {
  description = "Aggregation function and group by for cpu_percentage detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ".mean(by=['Instance', 'azure_resource_name', 'azure_resource_group_name', 'azure_region'])"
}

variable "cpu_percentage_timer" {
  description = "Evaluation window for cpu_percentage detector (i.e. 5m, 20m, 1h, 1d)"
  type        = string
  default     = "10m"
}

variable "cpu_percentage_threshold_critical" {
  description = "Critical threshold for cpu_percentage detector"
  type        = number
  default     = 95
}

variable "cpu_percentage_threshold_major" {
  description = "Major threshold for cpu_percentage detector"
  type        = number
  default     = 90
}

# memory_percentage detectors

variable "memory_percentage_disabled" {
  description = "Disable all alerting rules for memory_percentage detector"
  type        = bool
  default     = null
}

variable "memory_percentage_disabled_critical" {
  description = "Disable critical alerting rule for memory_percentage detector"
  type        = bool
  default     = null
}

variable "memory_percentage_disabled_major" {
  description = "Disable major alerting rule for memory_percentage detector"
  type        = bool
  default     = null
}

variable "memory_percentage_notifications" {
  description = "Notification recipients list per severity overridden for memory_percentage detector"
  type        = map(list(string))
  default     = {}
}

variable "memory_percentage_aggregation_function" {
  description = "Aggregation function and group by for memory_percentage detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ".mean(by=['Instance', 'azure_resource_name', 'azure_resource_group_name', 'azure_region'])"
}

variable "memory_percentage_timer" {
  description = "Evaluation window for memory_percentage detector (i.e. 5m, 20m, 1h, 1d)"
  type        = string
  default     = "5m"
}

variable "memory_percentage_threshold_critical" {
  description = "Critical threshold for memory_percentage detector"
  type        = number
  default     = 95
}

variable "memory_percentage_threshold_major" {
  description = "Major threshold for memory_percentage detector"
  type        = number
  default     = 90
}
