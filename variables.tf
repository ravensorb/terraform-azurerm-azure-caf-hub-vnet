variable "create_resource_group" {
  description = "Whether to create resource group and use it for all networking resources"
  default     = true
}

variable "resource_group_name" {
  description = "A container that holds related resources for an Azure solution"
  default     = ""
}

variable "location" {
  description = "The location/region to keep all your network resources. To get the list of all locations with table format from azure cli, run 'az account list-locations -o table'"
  default     = ""
}

variable "resource_prefix" {
  description = "(Optional) Prefix to use for all resoruces created (Defaults to resource_group_name)"
  default     = ""
}

variable "hub_vnet_name" {
  description = "The name of the virtual network"
  default     = ""
}

variable "vnet_address_space" {
  description = "The address space to be used for the Azure virtual network."
  default     = ["10.0.0.0/16"]
}

variable "create_ddos_plan" {
  description = "Create an ddos plan - Default is false"
  default     = true
}

variable "dns_servers" {
  description = "List of dns servers to use for virtual network"
  default     = []
}

variable "create_network_watcher" {
  description = "Controls if Network Watcher resources should be created for the Azure subscription"
  default     = true
}

variable "subnets" {
  description = "For each subnet, create an object that contain fields"
  default     = {}
}

variable "private_dns_zone_name" {
  description = "The name of the Private DNS zone"
  default     = null
}

variable "create_log_analytics_resource_group" {
  description = "Indicate if the log analytics related resources should be created in their own resource group"
  default     = false
}

variable "limit_network_log_analytics_storage_account_network_access" {
  description = "Limit log analytics storage account to hub vnet"
  default     = false
}

variable "log_analytics_workspace_sku" {
  description = "The Sku of the Log Analytics Workspace. Possible values are Free, PerNode, Premium, Standard, Standalone, Unlimited, and PerGB2018"
  default     = "PerGB2018"
}

variable "log_analytics_logs_retention_in_days" {
  description = "The log analytics workspace data retention in days. Possible values range between 30 and 730."
  default     = 30
}

variable "nsg_diag_logs" {
  description = "NSG Monitoring Category details for Azure Diagnostic setting"
  default     = ["NetworkSecurityGroupEvent", "NetworkSecurityGroupRuleCounter"]
}

variable "firewall_subnet_name" {
  description = "Indicate the name of the firewall subnet (ONLY set this if NOT using an azure firewall)"
  default     = null
}

variable "create_firewall" {
  description = "Indicate if an azure firewall should be created"
  default     = true
}

variable "firewall_service_endpoints" {
  description = "Service endpoints to add to the firewall subnet"
  type        = list(string)
  default = [
    "Microsoft.AzureActiveDirectory",
    "Microsoft.AzureCosmosDB",
    "Microsoft.EventHub",
    "Microsoft.KeyVault",
    "Microsoft.ServiceBus",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]
}

variable "public_ip_names" {
  description = "Public ips is a list of ip names that are connected to the firewall. At least one is required."
  type        = list(string)
  default     = ["fw-public"]
}

variable "gateway_subnet_address_prefix" {
  description = "The address prefix to use for the gateway subnet"
  default     = null
}

variable "firewall_subnet_address_prefix" {
  description = "The address prefix to use for the Firewall subnet"
  default     = []
}

variable "firewall_zones" {
  description = "A collection of availability zones to spread the Firewall over"
  type        = list(string)
  default     = null
}

variable "firewall_application_rules" {
  description = "List of application rules to apply to firewall."
  type        = list(object({ name = string, action = string, source_addresses = list(string), target_fqdns = list(string), protocol = object({ type = string, port = string }) }))
  default     = []
}

variable "firewall_network_rules" {
  description = "List of network rules to apply to firewall."
  type        = list(object({ name = string, action = string, source_addresses = list(string), destination_ports = list(string), destination_addresses = list(string), protocols = list(string) }))
  default     = []
}

variable "firewall_nat_rules" {
  description = "List of nat rules to apply to firewall."
  type        = list(object({ name = string, action = string, source_addresses = list(string), destination_ports = list(string), destination_addresses = list(string), protocols = list(string), translated_address = string, translated_port = string }))
  default     = []
}

variable "fw_pip_diag_logs" {
  description = "Firewall Public IP Monitoring Category details for Azure Diagnostic setting"
  default     = ["DDoSProtectionNotifications", "DDoSMitigationFlowLogs", "DDoSMitigationReports"]
}

variable "fw_diag_logs" {
  description = "Firewall Monitoring Category details for Azure Diagnostic setting"
  default     = ["AzureFirewallApplicationRule", "AzureFirewallNetworkRule", "AzureFirewallDnsProxy"]
}

variable "storage_account" { 
  description = "Details on the storage acccount"
  type        = object({ create = bool, tier = string, replication = string})
  default     = {
    create      = true
    tier        = "Standard"
    replication = "ZRS"
  }
}

variable "create_public_ip_prefix" {
  description = "(Optional) Indicates if a new public ip prefix should be created (default true)"
  default     = true
}

variable "public_ip_prefix_resource_group_name" {
  description = "(Optional) The resource group that contains the public ip prefix (defaults to hub resource group)"
  default     = null
}

variable "public_ip_prefix_name" {
  description = "(Optional) The name of the public prefix to use"
  default     = null
}

variable "route_table" {
  description = "(Optional) Additional route table entries"
  type        = list(object( { name = string, address_prefix = string, next_hop_type = string, next_hop_in_ip_address = string} ))
  default     = []
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
