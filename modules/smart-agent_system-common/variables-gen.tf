# heartbeat detector

variable "heartbeat_notifications" {
  description = "Notification recipients list per severity overridden for heartbeat detector"
  type        = map(list(string))
  default     = {}
}

variable "heartbeat_aggregation_function" {
  description = "Aggregation function and group by for heartbeat detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "heartbeat_disabled" {
  description = "Disable all alerting rules for heartbeat detector"
  type        = bool
  default     = null
}

variable "heartbeat_timeframe" {
  description = "Timeframe for heartbeat detector (i.e. \"10m\")"
  type        = string
  default     = "20m"
}

# cpu detector

variable "cpu_notifications" {
  description = "Notification recipients list per severity overridden for cpu detector"
  type        = map(list(string))
  default     = {}
}

variable "cpu_aggregation_function" {
  description = "Aggregation function and group by for cpu detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "cpu_transformation_function" {
  description = "Transformation function for cpu detector (i.e. \".mean(over='5m')\")"
  type        = string
  default     = ".min(over='1h')"
}

variable "cpu_disabled" {
  description = "Disable all alerting rules for cpu detector"
  type        = bool
  default     = null
}

variable "cpu_disabled_critical" {
  description = "Disable critical alerting rule for cpu detector"
  type        = bool
  default     = null
}

variable "cpu_disabled_major" {
  description = "Disable major alerting rule for cpu detector"
  type        = bool
  default     = null
}

variable "cpu_threshold_critical" {
  description = "Critical threshold for cpu detector"
  type        = number
  default     = 90
}

variable "cpu_threshold_major" {
  description = "Major threshold for cpu detector"
  type        = number
  default     = 85
}

# load detector

variable "load_notifications" {
  description = "Notification recipients list per severity overridden for load detector"
  type        = map(list(string))
  default     = {}
}

variable "load_aggregation_function" {
  description = "Aggregation function and group by for load detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "load_transformation_function" {
  description = "Transformation function for load detector (i.e. \".mean(over='5m')\")"
  type        = string
  default     = ".min(over='30m')"
}

variable "load_disabled" {
  description = "Disable all alerting rules for load detector"
  type        = bool
  default     = null
}

variable "load_disabled_critical" {
  description = "Disable critical alerting rule for load detector"
  type        = bool
  default     = null
}

variable "load_disabled_major" {
  description = "Disable major alerting rule for load detector"
  type        = bool
  default     = null
}

variable "load_threshold_critical" {
  description = "Critical threshold for load detector"
  type        = number
  default     = 2.5
}

variable "load_threshold_major" {
  description = "Major threshold for load detector"
  type        = number
  default     = 2
}

# disk_space detector

variable "disk_space_notifications" {
  description = "Notification recipients list per severity overridden for disk_space detector"
  type        = map(list(string))
  default     = {}
}

variable "disk_space_aggregation_function" {
  description = "Aggregation function and group by for disk_space detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "disk_space_transformation_function" {
  description = "Transformation function for disk_space detector (i.e. \".mean(over='5m')\")"
  type        = string
  default     = ".max(over='5m')"
}

variable "disk_space_disabled" {
  description = "Disable all alerting rules for disk_space detector"
  type        = bool
  default     = null
}

variable "disk_space_disabled_critical" {
  description = "Disable critical alerting rule for disk_space detector"
  type        = bool
  default     = null
}

variable "disk_space_disabled_major" {
  description = "Disable major alerting rule for disk_space detector"
  type        = bool
  default     = null
}

variable "disk_space_threshold_critical" {
  description = "Critical threshold for disk_space detector"
  type        = number
  default     = 90
}

variable "disk_space_threshold_major" {
  description = "Major threshold for disk_space detector"
  type        = number
  default     = 80
}

# disk_inodes detector

variable "disk_inodes_notifications" {
  description = "Notification recipients list per severity overridden for disk_inodes detector"
  type        = map(list(string))
  default     = {}
}

variable "disk_inodes_aggregation_function" {
  description = "Aggregation function and group by for disk_inodes detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "disk_inodes_transformation_function" {
  description = "Transformation function for disk_inodes detector (i.e. \".mean(over='5m')\")"
  type        = string
  default     = ".max(over='5m')"
}

variable "disk_inodes_disabled" {
  description = "Disable all alerting rules for disk_inodes detector"
  type        = bool
  default     = null
}

variable "disk_inodes_disabled_critical" {
  description = "Disable critical alerting rule for disk_inodes detector"
  type        = bool
  default     = null
}

variable "disk_inodes_disabled_major" {
  description = "Disable major alerting rule for disk_inodes detector"
  type        = bool
  default     = null
}

variable "disk_inodes_threshold_critical" {
  description = "Critical threshold for disk_inodes detector"
  type        = number
  default     = 95
}

variable "disk_inodes_threshold_major" {
  description = "Major threshold for disk_inodes detector"
  type        = number
  default     = 90
}

# memory detector

variable "memory_notifications" {
  description = "Notification recipients list per severity overridden for memory detector"
  type        = map(list(string))
  default     = {}
}

variable "memory_aggregation_function" {
  description = "Aggregation function and group by for memory detector (i.e. \".mean(by=['host'])\")"
  type        = string
  default     = ""
}

variable "memory_transformation_function" {
  description = "Transformation function for memory detector (i.e. \".mean(over='5m')\")"
  type        = string
  default     = ".min(over='5m')"
}

variable "memory_disabled" {
  description = "Disable all alerting rules for memory detector"
  type        = bool
  default     = null
}

variable "memory_disabled_critical" {
  description = "Disable critical alerting rule for memory detector"
  type        = bool
  default     = null
}

variable "memory_disabled_major" {
  description = "Disable major alerting rule for memory detector"
  type        = bool
  default     = null
}

variable "memory_threshold_critical" {
  description = "Critical threshold for memory detector"
  type        = number
  default     = 95
}

variable "memory_threshold_major" {
  description = "Major threshold for memory detector"
  type        = number
  default     = 90
}
