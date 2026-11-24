locals {
  suffix = substr(sha256(var.run_id), 0, 10)
  name   = "hashbox-builder-${local.suffix}"
  tags = {
    purpose           = "hashbox-builder"
    lifecycle         = "ephemeral"
    run_id            = var.run_id
    hashbox_demo_run  = var.run_id
    hashbox_demo_role = "builder"
  }
}

resource "azurerm_resource_group" "builder" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "builder" {
  name                = "${local.name}-vnet"
  address_space       = ["10.91.0.0/16"]
  location            = azurerm_resource_group.builder.location
  resource_group_name = azurerm_resource_group.builder.name
  tags                = local.tags
}

resource "azurerm_subnet" "builder" {
  name                 = "builder"
  resource_group_name  = azurerm_resource_group.builder.name
  virtual_network_name = azurerm_virtual_network.builder.name
  address_prefixes     = ["10.91.1.0/24"]
}

resource "azurerm_network_security_group" "builder" {
  name                = "${local.name}-nsg"
  location            = azurerm_resource_group.builder.location
  resource_group_name = azurerm_resource_group.builder.name
  tags                = local.tags

  security_rule {
    name                       = "AllowOperatorSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.ssh_source_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "builder" {
  name                = "${local.name}-pip"
  location            = azurerm_resource_group.builder.location
  resource_group_name = azurerm_resource_group.builder.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "builder" {
  name                = "${local.name}-nic"
  location            = azurerm_resource_group.builder.location
  resource_group_name = azurerm_resource_group.builder.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.builder.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.builder.id
  }
}

resource "azurerm_network_interface_security_group_association" "builder" {
  network_interface_id      = azurerm_network_interface.builder.id
  network_security_group_id = azurerm_network_security_group.builder.id
}

resource "azurerm_linux_virtual_machine" "builder" {
  name                            = local.name
  resource_group_name             = azurerm_resource_group.builder.name
  location                        = azurerm_resource_group.builder.location
  size                            = var.vm_size
  admin_username                  = "hashbox-builder"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.builder.id]
  provision_vm_agent              = true
  custom_data                     = base64encode(file("${path.module}/cloud-init.yaml"))
  tags                            = local.tags

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = "hashbox-builder"
    public_key = var.ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = var.source_image_version
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 256
  }

  boot_diagnostics {}
}
