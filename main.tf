#---------------------------------
# Local declarations
#---------------------------------
locals {
  resource_group_name = element(coalescelist(data.azurerm_resource_group.rgrp.*.name, azurerm_resource_group.rg.*.name, [""]), 0)
  resource_prefix     = var.resource_prefix == "" ? local.resource_group_name : var.resource_prefix
  location            = element(coalescelist(data.azurerm_resource_group.rgrp.*.location, azurerm_resource_group.rg.*.location, [""]), 0)
  if_ddos_enabled     = var.create_ddos_plan ? [{}] : []
  public_ip_map       = { for pip in var.public_ip_names : pip => true }

  fw_nat_rules = { for idx, rule in var.firewall_nat_rules : rule.name => {
    idx : idx,
    rule : rule,
    }
  }

  fw_network_rules = { for idx, rule in var.firewall_network_rules : rule.name => {
    idx : idx,
    rule : rule,
    }
  }

  fw_application_rules = { for idx, rule in var.firewall_application_rules : rule.name => {
    idx : idx,
    rule : rule,
    }
  }

  timeout_create  = "15m"
  timeout_update  = "15m"
  timeout_delete  = "15m"
  timeout_read    = "15m"
}

#---------------------------------------------------------
# Resource Group Creation or selection - Default is "true"
#----------------------------------------------------------
data "azurerm_resource_group" "rgrp" {
  count = var.create_resource_group == false ? 1 : 0
  name  = var.resource_group_name
}

resource "azurerm_resource_group" "rg" {
  count    = var.create_resource_group ? 1 : 0
  name     = lower(var.resource_group_name)
  location = var.location
  tags     = merge({ "ResourceName" = format("%s", var.resource_group_name) }, var.tags, )
}

#-------------------------------------
# VNET Creation - Default is "true"
#-------------------------------------
resource "azurerm_virtual_network" "vnet" {
  name                = lower("${local.resource_prefix}-vnet")
  location            = local.location
  resource_group_name = local.resource_group_name
  address_space       = var.vnet_address_space
  dns_servers         = var.dns_servers
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-vnet") }, var.tags, )

  dynamic "ddos_protection_plan" {
    for_each = local.if_ddos_enabled

    content {
      id     = azurerm_network_ddos_protection_plan.ddos[0].id
      enable = true
    }
  }
}

#--------------------------------------------
# Ddos protection plan - Default is "true"
#--------------------------------------------
resource "azurerm_network_ddos_protection_plan" "ddos" {
  count               = var.create_ddos_plan ? 1 : 0
  name                = lower("${local.resource_prefix}-ddos-protection-plan")
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-ddos-protection-plan") }, var.tags, )
}

#-------------------------------------
# Network Watcher - Default is "true"
#-------------------------------------
resource "azurerm_resource_group" "nwatcher" {
  count    = var.create_network_watcher != false ? 1 : 0
  name     = "NetworkWatcherRG"
  location = local.location
  tags     = merge({ "ResourceName" = "NetworkWatcherRG" }, var.tags, )
}

resource "azurerm_network_watcher" "nwatcher" {
  count               = var.create_network_watcher != false ? 1 : 0
  name                = "${local.resource_prefix}-nw"
  location            = local.location
  resource_group_name = azurerm_resource_group.nwatcher.0.name
  tags                = merge({ "ResourceName" = format("%s", "${local.resource_prefix}-nw") }, var.tags, )
}

#--------------------------------------------------------------------------------------------------------
# Subnets Creation with, private link endpoint/servie network policies, service endpoints and Deligation.
#--------------------------------------------------------------------------------------------------------
resource "azurerm_subnet" "fw-snet" {
  name                 = var.firewall_subnet_name != null ? var.firewall_subnet_name : "AzureFirewallSubnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.firewall_subnet_address_prefix #[cidrsubnet(element(var.vnet_address_space, 0), 10, 0)]
  service_endpoints    = var.firewall_service_endpoints
}

resource "azurerm_subnet" "gw_snet" {
  count                = var.gateway_subnet_address_prefix != null ? 1 : 0
  name                 = "GatewaySubnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.gateway_subnet_address_prefix #[cidrsubnet(element(var.vnet_address_space, 0), 8, 1)]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "snet" {
  for_each             = var.subnets
  name                 = lower(format("${local.resource_prefix}-${var.hub_vnet_name}-snet-%s", each.value.subnet_name))
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = each.value.subnet_address_prefix
  service_endpoints    = lookup(each.value, "service_endpoints", [])
  # Applicable to the subnets which used for Private link endpoints or services 
  enforce_private_link_endpoint_network_policies = lookup(each.value, "enforce_private_link_endpoint_network_policies", null)
  enforce_private_link_service_network_policies  = lookup(each.value, "enforce_private_link_service_network_policies", null)

  dynamic "delegation" {
    for_each = lookup(each.value, "delegation", {}) != {} ? [1] : []
    content {
      name = lookup(each.value.delegation, "name", null)
      service_delegation {
        name    = lookup(each.value.delegation.service_delegation, "name", null)
        actions = lookup(each.value.delegation.service_delegation, "actions", null)
      }
    }
  }
}

#---------------------------------------------------------------
# Network security group - NSG created for every subnet in VNet
#---------------------------------------------------------------
resource "azurerm_network_security_group" "nsg" {
  for_each            = var.subnets
  name                = lower("${local.resource_prefix}-nsg-${each.key}")
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-nsg-${each.key}-in") }, var.tags, )
  dynamic "security_rule" {
    for_each = concat(lookup(each.value, "nsg_inbound_rules", []), lookup(each.value, "nsg_outbound_rules", []))
    content {
      name                       = security_rule.value[0] == "" ? "Default_Rule" : security_rule.value[0]
      priority                   = security_rule.value[1]
      direction                  = security_rule.value[2] == "" ? "Inbound" : security_rule.value[2]
      access                     = security_rule.value[3] == "" ? "Allow" : security_rule.value[3]
      protocol                   = security_rule.value[4] == "" ? "Tcp" : security_rule.value[4]
      source_port_range          = "*"
      destination_port_range     = security_rule.value[5] == "" ? "*" : security_rule.value[5]
      source_address_prefix      = security_rule.value[6] == "" ? element(each.value.subnet_address_prefix, 0) : security_rule.value[6]
      destination_address_prefix = security_rule.value[7] == "" ? element(each.value.subnet_address_prefix, 0) : security_rule.value[7]
      description                = "${security_rule.value[2]}_Port_${security_rule.value[5]}"
    }
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

resource "azurerm_subnet_network_security_group_association" "nsg-assoc" {
  for_each                  = var.subnets
  subnet_id                 = azurerm_subnet.snet[each.key].id
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
}

#-------------------------------------------------
# route_table to dirvert traffic through Firewall
#-------------------------------------------------
resource "azurerm_route_table" "rtout" {
  name                = "${local.resource_prefix}-route-network-outbound"
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = "route-network-outbound" }, var.tags, )
}

resource "azurerm_subnet_route_table_association" "rtassoc" {
  for_each       = var.subnets
  subnet_id      = azurerm_subnet.snet[each.key].id
  route_table_id = azurerm_route_table.rtout.id
}

resource "azurerm_route" "rt" {
  count                  = var.create_firewall ? 1 : 0
  name                   = lower("${local.resource_prefix}-route-to-firewall")
  resource_group_name    = var.resource_group_name
  route_table_name       = azurerm_route_table.rtout.name
  address_prefix         = "0.0.0.0/0"
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.fw.0.ip_configuration.0.private_ip_address
}

#----------------------------------------
# Private DNS Zone - Default is "true"
#----------------------------------------
resource "azurerm_private_dns_zone" "dz" {
  count               = var.private_dns_zone_name != null ? 1 : 0
  name                = var.private_dns_zone_name
  resource_group_name = local.resource_group_name
  tags                = merge({ "ResourceName" = format("%s", lower(var.private_dns_zone_name)) }, var.tags, )
}

resource "azurerm_private_dns_zone_virtual_network_link" "dzvlink" {
  count                 = var.private_dns_zone_name != null ? 1 : 0
  name                  = lower("${var.private_dns_zone_name}-link")
  resource_group_name   = local.resource_group_name
  virtual_network_id    = azurerm_virtual_network.vnet.id
  private_dns_zone_name = azurerm_private_dns_zone.dz[0].name
  tags                  = merge({ "ResourceName" = format("%s", lower("${var.private_dns_zone_name}-link")) }, var.tags, )
}

#----------------------------------------------------------------
# Azure Role Assignment for Service Principal - current user
#-----------------------------------------------------------------
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "peering" {
  scope                = azurerm_virtual_network.vnet.id
  role_definition_name = "Network Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "dns" {
  scope                = azurerm_private_dns_zone.dz[0].id
  role_definition_name = "Private DNS Zone Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

#------------------------------------------
# Public IP resources for Azure Firewall
#------------------------------------------
resource "random_string" "str" {
  for_each = local.public_ip_map
  length   = 6
  special  = false
  upper    = false
  keepers = {
    domain_name_label = each.key
  }
}

resource "azurerm_public_ip_prefix" "pip_prefix" {
  name                = lower("${local.resource_prefix}-pip-prefix")
  location            = local.location
  resource_group_name = local.resource_group_name
  prefix_length       = 30
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-pip-prefix") }, var.tags, )
}

resource "azurerm_public_ip" "fw-pip" {
  for_each            = local.public_ip_map
  name                = lower("${local.resource_prefix}-pip-${each.key}")
  location            = local.location
  resource_group_name = local.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  public_ip_prefix_id = azurerm_public_ip_prefix.pip_prefix.id
  domain_name_label   = format("%s%s", lower(replace(each.key, "/[[:^alnum:]]/", "")), random_string.str[each.key].result)
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-pip-${each.key}") }, var.tags, )

  lifecycle {
    ignore_changes = [
      tags,
      ip_tags,
    ]
  }  
}

#-----------------
# Azure Firewall 
#-----------------
resource "azurerm_firewall" "fw" {
  count               = var.create_firewall ? 1 : 0
  name                = lower("${local.resource_prefix}-fw")
  location            = local.location
  resource_group_name = local.resource_group_name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  zones               = var.firewall_zones
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-fw") }, var.tags, )

  dynamic "ip_configuration" {
    for_each = local.public_ip_map
    iterator = ip
    content {
      name                 = ip.key
      subnet_id            = ip.key == var.public_ip_names[0] ? azurerm_subnet.fw-snet.id : null
      public_ip_address_id = azurerm_public_ip.fw-pip[ip.key].id
    }
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

#----------------------------------------------
# Azure Firewall Network/Application/NAT Rules 
#----------------------------------------------
resource "azurerm_firewall_application_rule_collection" "fw_app" {
  for_each            = { for k in local.fw_application_rules : k => k if var.create_firewall } 
  name                = lower(format("${local.resource_prefix}-fw-app-rule-%s", each.key))
  azure_firewall_name = azurerm_firewall.fw.0.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name             = each.key
    source_addresses = each.value.rule.source_addresses
    target_fqdns     = each.value.rule.target_fqdns

    protocol {
      type = each.value.rule.protocol.type
      port = each.value.rule.protocol.port
    }
  }
}

resource "azurerm_firewall_network_rule_collection" "fw" {
  for_each            = { for k in local.fw_network_rules : k => k if var.create_firewall }
  name                = lower(format("${local.resource_prefix}-fw-net-rule-%s", each.key))
  azure_firewall_name = azurerm_firewall.fw.0.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name                  = each.key
    source_addresses      = each.value.rule.source_addresses
    destination_ports     = each.value.rule.destination_ports
    destination_addresses = [for dest in each.value.rule.destination_addresses : contains(var.public_ip_names, dest) ? azurerm_public_ip.fw-pip[dest].ip_address : dest]
    protocols             = each.value.rule.protocols
  }
}

resource "azurerm_firewall_nat_rule_collection" "fw" {
  for_each            = { for k in local.fw_nat_rules : k => k if var.create_firewall }
  name                = lower(format("${local.resource_prefix}-fw-nat-rule-%s", each.key))
  azure_firewall_name = azurerm_firewall.fw.0.name
  resource_group_name = local.resource_group_name
  priority            = 100 * (each.value.idx + 1)
  action              = each.value.rule.action

  rule {
    name                  = each.key
    source_addresses      = each.value.rule.source_addresses
    destination_ports     = each.value.rule.destination_ports
    destination_addresses = [for dest in each.value.rule.destination_addresses : contains(var.public_ip_names, dest) ? azurerm_public_ip.fw-pip[dest].ip_address : dest]
    protocols             = each.value.rule.protocols
    translated_address    = each.value.rule.translated_address
    translated_port       = each.value.rule.translated_port
  }
}

#-----------------------------------------------
# Storage Account for Logs Archive
#-----------------------------------------------
data "azurerm_resource_group" "rgstp" {
  count     = var.create_log_analytics_resource_group ? 0 : 0
  name      = lower("${var.resource_prefix}-rg-law") 
}

resource "azurerm_resource_group" "rgst" {
  count    = var.create_log_analytics_resource_group ? 1 : 0
  name     = lower("${var.resource_prefix}-rg-law")
  location = local.location
  tags     = merge({ "ResourceName" = lower("${var.resource_prefix}-rg-law") }, var.tags, )
}

resource "azurerm_storage_account" "storeacc" {
  name                      = format("%sstlogs", lower(replace(local.resource_prefix, "/[[:^alnum:]]/", "")))
  resource_group_name       = var.create_log_analytics_resource_group ? lower("${var.resource_prefix}-rg-law") : var.resource_group_name
  location                  = local.location
  account_kind              = "StorageV2"
  account_tier              = var.storage_account.tier
  account_replication_type  = var.storage_account.replication
  enable_https_traffic_only = true
  tags                      = merge({ "ResourceName" = format("%sstlogs", lower(replace(local.resource_prefix, "/[[:^alnum:]]/", ""))) }, var.tags, )
}

## Azure built-in roles
## https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

# data "azuread_service_principal" "af_sasp" {
#   #object_id = "07cdd199-8f98-4b25-9a89-e50b2b604a28" # Microsoft.StorageSync
#   display_name = "Microsoft.StorageSync"
# }

resource "azurerm_role_assignment" "storeacc-ra-rdac" {
  count                 = var.limit_network_log_analytics_storage_account_network_access ? 1 : 0
  scope                 = azurerm_storage_account.storeacc.id
  role_definition_name  = "Reader and Data Access"  
  principal_id          = "Microsoft.StorageSync" #data.azuread_service_principal.af_sasp.id
}

# Storage Account Network rules
resource "azurerm_storage_account_network_rules" "storeacc-netrules" {  
  count                       = var.limit_network_log_analytics_storage_account_network_access ? 1 : 0
  storage_account_id          = azurerm_storage_account.storeacc.id
  virtual_network_subnet_ids  = [ concat(azurerm_subnet.snet.*.id, [""]) ]
  default_action              = "Deny"
  
  bypass = [
    "Metrics",
    "Logging",
    "AzureServices"
  ]
}

#-----------------------------------------------
# Log analytics workspace for Logs analysis
#-----------------------------------------------
resource "random_string" "main" {
  length  = 8
  special = false
  keepers = {
    name = var.hub_vnet_name
  }
}

resource "azurerm_log_analytics_workspace" "logws" {
  name                = lower("${local.resource_prefix}-logaws")
  resource_group_name = azurerm_storage_account.storeacc.resource_group_name
  location            = local.location
  sku                 = var.log_analytics_workspace_sku
  retention_in_days   = var.log_analytics_logs_retention_in_days
  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-logaws") }, var.tags, )
}

#-----------------------------------------
# Network flow logs for subnet and NSG
#-----------------------------------------
resource "azurerm_network_watcher_flow_log" "nwflog" {
  for_each                  = var.subnets
  name                      = lower("${local.resource_prefix}-nwflog-${each.key}")
  network_watcher_name      = azurerm_network_watcher.nwatcher[0].name
  resource_group_name       = azurerm_resource_group.nwatcher[0].name # Must provide Netwatcher resource Group
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
  storage_account_id        = azurerm_storage_account.storeacc.id
  enabled                   = true
  version                   = 2
  retention_policy {
    enabled = true
    days    = 15
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.logws.workspace_id
    workspace_region      = local.location
    workspace_resource_id = azurerm_log_analytics_workspace.logws.id
    interval_in_minutes   = 10
  }

  depends_on = [
    azurerm_storage_account.storeacc,
    azurerm_network_watcher.nwatcher,
    azurerm_resource_group.nwatcher,
    azurerm_network_security_group.nsg,
    azurerm_log_analytics_workspace.logws
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#---------------------------------------------------------------
# azurerm monitoring diagnostics - VNet, NSG, PIP, and Firewall
#---------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "vnet" {
  name                       = lower("${local.resource_prefix}-vnet-diag")
  target_resource_id         = azurerm_virtual_network.vnet.id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id
  log {
    category = "VMProtectionAlerts"
    enabled  = true

    retention_policy {
      enabled = false
    }
  }
  metric {
    category = "AllMetrics"

    retention_policy {
      enabled = false
    }
  }

  depends_on = [
    azurerm_storage_account.storeacc
  ]

}

resource "azurerm_monitor_diagnostic_setting" "nsg" {
  for_each                   = var.subnets
  name                       = lower("${local.resource_prefix}-${each.key}-diag")
  target_resource_id         = azurerm_network_security_group.nsg[each.key].id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id

  dynamic "log" {
    for_each = var.nsg_diag_logs
    content {
      category = log.value
      enabled  = true

      retention_policy {
        enabled = false
      }
    }
  }

  depends_on = [
    azurerm_storage_account.storeacc
  ]
}

resource "azurerm_monitor_diagnostic_setting" "fw-diag" {
  count                      = var.create_firewall ? 1 : 0
  name                       = lower("${local.resource_prefix}-fw-diag")
  target_resource_id         = azurerm_firewall.fw.0.id
  storage_account_id         = azurerm_storage_account.storeacc.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logws.id

  dynamic "log" {
    for_each = var.fw_diag_logs
    content {
      category = log.value
      enabled  = true

      retention_policy {
        enabled = false
      }
    }
  }

  metric {
    category = "AllMetrics"

    retention_policy {
      enabled = false
    }
  }

  depends_on = [
    azurerm_storage_account.storeacc
  ]
}
