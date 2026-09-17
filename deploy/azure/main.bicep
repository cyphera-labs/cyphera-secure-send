// Cyphera SecureSend on Azure Container Apps, standalone shape: exactly one
// replica, messages in process memory, management port private.
// Compile to azuredeploy.json for the Deploy to Azure button:
//   bicep build main.bicep --outfile azuredeploy.json

targetScope = 'resourceGroup'

@description('Name prefix for the resources.')
@minLength(3)
@maxLength(20)
param name string = 'securesend'

@description('Region. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Container image. Pin a version tag in production.')
param image string = 'ghcr.io/cyphera-labs/cyphera-secure-send:latest'

@description('Company name shown in the interface.')
param companyName string = ''

@description('Primary brand color, #rgb or #rrggbb.')
param primaryColor string = '#1f4e79'

@description('anonymous: anyone with the link and the password. oidc: sign-in required, recipient binding on.')
@allowed(['anonymous', 'oidc'])
param authMode string = 'anonymous'

@description('OIDC issuer. For Entra ID: https://login.microsoftonline.com/<tenant-id>/v2.0')
param oidcIssuer string = ''

@description('OIDC client (application) id.')
param oidcClientId string = ''

@description('OIDC client secret. Stored as a Container Apps secret.')
@secure()
param oidcClientSecret string = ''

@description('Comma-separated list of allowed email domains, e.g. example.com. Empty allows any.')
param allowedDomains string = ''

@description('Default message lifetime in seconds. Must be one of 300, 900, 3600, 28800, 86400.')
@allowed([300, 900, 3600, 28800, 86400])
param defaultTtlSeconds int = 3600

@description('Memory budget for pending messages, in bytes.')
param memoryBudgetBytes int = 134217728

var envName = '${name}-env'
var appName = '${name}-app'
var logName = '${name}-logs'
var publicBaseUrl = 'https://${appName}.${env.properties.defaultDomain}'
var oidcEnabled = authMode == 'oidc'

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      // One instance only: the memory backend cannot be shared.
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      secrets: oidcEnabled ? [
        {
          name: 'oidc-client-secret'
          value: oidcClientSecret
        }
      ] : []
    }
    template: {
      containers: [
        {
          name: 'securesend'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: concat([
            { name: 'CYPHERA_SECURESEND__SERVER__PUBLIC_BASE_URL', value: publicBaseUrl }
            { name: 'CYPHERA_SECURESEND__SERVER__HSTS', value: 'true' }
            { name: 'CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND', value: '0.0.0.0:9090' }
            // The Container Apps ingress proxies from the environment's internal range.
            { name: 'CYPHERA_SECURESEND__SERVER__TRUSTED_PROXIES', value: '10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16' }
            { name: 'CYPHERA_SECURESEND__MESSAGES__DEFAULT_TTL_SECONDS', value: string(defaultTtlSeconds) }
            { name: 'CYPHERA_SECURESEND__MESSAGES__MEMORY_BUDGET_BYTES', value: string(memoryBudgetBytes) }
            { name: 'CYPHERA_SECURESEND__BRANDING__COMPANY_NAME', value: companyName }
            { name: 'CYPHERA_SECURESEND__BRANDING__COLORS__PRIMARY', value: primaryColor }
            { name: 'CYPHERA_SECURESEND__AUTH__MODE', value: authMode }
          ], oidcEnabled ? [
            { name: 'CYPHERA_SECURESEND__AUTH__OIDC__ISSUER', value: oidcIssuer }
            { name: 'CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_ID', value: oidcClientId }
            { name: 'CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_SECRET', secretRef: 'oidc-client-secret' }
            { name: 'CYPHERA_SECURESEND__AUTH__OIDC__ALLOWED_DOMAINS', value: allowedDomains }
          ] : [])
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/livez', port: 9090 }
              periodSeconds: 10
            }
            {
              type: 'Readiness'
              httpGet: { path: '/readyz', port: 9090 }
              periodSeconds: 5
            }
          ]
        }
      ]
      scale: {
        // Never zero (messages would vanish on idle) and never more than one.
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output url string = publicBaseUrl
output oidcRedirectUri string = '${publicBaseUrl}/auth/callback'
