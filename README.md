# Azure app gateway with azfw

This creates a resource group, a vnet with an Application gateway with an Azure firewall behind it inspecting TLS, a webapp and a separate vnet with a client VM with an edited hosts file pointing testcert.com to the application gateway frontend. The client Windows VM has your public ip added to an NSG allowing RDP access. A keyvault is created and self-signed certificates are generated and put in the keyvault for the Application gateway to use for SSL termination and also installed on the client VM. Another set of self signed certificates are on the app gateway backend and firewall for end to end TLS. This also creates a logic app that will delete the resource group in 24hrs. You'll be prompted for the resource group name, location where you want the resources created, your public ip and username and password to use for the VM's. From the client VM you can test reaching https://testcert.com and get a response from the webapp.
Topology will look like this 

![appgwwithazfwlab](https://github.com/quiveringbacon/Azureappgatewaywithazfw/assets/128983862/04b41e5b-d8f9-45ae-abc7-5b8b9ffdb5b1)

You can run Terraform right from the Azure cloud shell by cloning this git repository with "git clone https://github.com/quiveringbacon/Azureappgatewaywithazfw.git ./terraform".

Then, "cd terraform" then, "terraform init" and finally "terraform apply -auto-approve" to deploy.
