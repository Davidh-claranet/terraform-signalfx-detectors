output "cluster_status" {
  description = "Detector resource for cluster_status"
  value       = signalfx_detector.cluster_status
}

output "cpu_90_15min" {
  description = "Detector resource for cpu_90_15min"
  value       = signalfx_detector.cpu_90_15min
}

output "fivexx_http_response" {
  description = "Detector resource for fivexx_http_response"
  value       = signalfx_detector.fivexx_http_response
}

output "fourxx_http_response" {
  description = "Detector resource for fourxx_http_response"
  value       = signalfx_detector.fourxx_http_response
}

output "free_space" {
  description = "Detector resource for free_space"
  value       = signalfx_detector.free_space
}

output "heartbeat" {
  description = "Detector resource for heartbeat"
  value       = signalfx_detector.heartbeat
}

output "jvm_memory_pressure" {
  description = "Detector resource for jvm_memory_pressure"
  value       = signalfx_detector.jvm_memory_pressure
}

