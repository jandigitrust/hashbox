output "public_ip" {
  value = azurerm_public_ip.builder.ip_address
}

output "resource_group" {
  value = azurerm_resource_group.builder.name
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.builder.name
}

output "builder_principal_id" {
  value = azurerm_linux_virtual_machine.builder.identity[0].principal_id
}

output "subnet_id" {
  value = azurerm_subnet.builder.id
}

output "vnet_id" {
  value = azurerm_virtual_network.builder.id
}
