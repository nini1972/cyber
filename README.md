# Cyber-Security Agent

## A Code Analyzer via Semgrep MCP server for Azure and GCP

![Course Image](assets/cyber.png)

_If you're looking at this in Cursor, please right click on the filename in the Explorer on the left, and select "Open preview", to view it in formatted glory._

### Welcome to the Week 3 Days 1 and 2 project..

Please clone this repo:

```bash
git clone https://github.com/ed-donner/cyber.git
```

Then open this as a project in Cursor; then head into the week3 directory and start with guide "day1.part0" - right click and select "Open Preview".

#### Keep in mind

- Please submit your community_contributions, including links to your repos, in the production repo community_contributions folder
- Regularly do a git pull to get the latest code
- Reach out in Udemy or email (ed@edwarddonner.com) if I can help!

login azure cli

# (optional) clear previous sessions
az logout

# Use device-code (opens a browser on microsoft.com/devicelogin where you can complete MFA)
az login --use-device-code

# If you need to target a specific tenant:
az login --use-device-code --tenant <TENANT_ID>

# After successful login, list subscriptions and set one as active
az account list --output table
az account set --subscription "<SUBSCRIPTION_NAME_OR_ID>"

# If you have no subscriptions but need to authenticate:
az login --use-device-code --allow-no-subscriptions


#Azure subscription 1  AzureCloud   e01af108-4d73-4191-b47a-75ed4e12e0c6  abcc15c5-3595-4d80-8104-6b2fdca592b2  Enabled  True#

Sempreg is a powerful static code analysis tool that can be used to find and fix security vulnerabilities in your code. It supports multiple languages and can be integrated into your CI/CD pipeline for continuous security checks.
#web_nini1972_valid-from-2026-02-10T13:44:06.309538#

#acr_login_server = "cyberanalyzern85ja6.azurecr.io"
#app_url = "https://cyber-analyzer.ambitiousbush-f1cd798f.westeurope.azurecontainerapps.io"
#resource_group = "cyber-analyzer-rg"

Actions taken
Installed nvm in WSL and installed Node 20.20.0 (npm 10.8.2); shell is now using the Linux Node instead of the Windows one.
Cleaned the frontend install artifacts (node_modules, old package-lock.json), reinstalled dependencies, and generated a fresh package-lock.json.
Ran the Next.js production build in WSL; it completed successfully.
Current status
npm run build now succeeds in frontend with Node v20.20.0.
Your package-lock was recreated for the Linux environment.
Next steps
In any new shell, load nvm before running npm commands: export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && nvm use 20 (add to your shell RC if you want it automatic).
Rerun terraform apply from azure now that the build passes. You’ll still need to import or rename the existing Log Analytics workspace as discussed earlier