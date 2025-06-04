// ============================================================================
// Azure Front Door Complete Bicep Template - Part 1
// Parameters and Variables Section
// ============================================================================

@description('The name of the Front Door profile')
param frontDoorName string

@description('The SKU of the Front Door profile')
@allowed([
  'Standard_AzureFrontDoor'
  'Premium_AzureFrontDoor'
])
param frontDoorSku string = 'Standard_AzureFrontDoor'

@description('Location for metadata resources')
param location string = resourceGroup().location

@description('Environment')
@allowed([
  'dev'
  'test'
  'prod'
])
param environment string = 'dev'

@description('Enable WAF Policy')
param enableWaf bool = true

@description('WAF Policy name')
param wafPolicyName string = '${frontDoorName}wafpolicy'

@description('WAF mode')
@allowed([
  'Detection'
  'Prevention'
])
param wafMode string = 'Detection'

@description('Rate limiting threshold per minute')
param rateLimitThreshold int = 1000

@description('Enable bot protection')
param enableBotProtection bool = true

@description('Enable geo filtering')
param enableGeoFiltering bool = false

@description('Allowed countries for geo filtering')
param allowedCountries array = ['US']

@description('Custom block response status code')
@allowed([403, 406, 429])
param customBlockResponseStatusCode int = 403

@description('Enable custom domains')
param enableCustomDomains bool = true

@description('Custom domain names')
param customDomains array = [
  {
    name: 'primary'
    hostName: 'usims.usims-dev.schools.utah.gov'
    certificateType: 'ManagedCertificate'
  }
  {
    name: 'secondary' 
    hostName: 'qa.usims-dev.schools.utah.gov'
    certificateType: 'ManagedCertificate'
  }
]

@description('Backend pool configurations')
param backendPools array = [
  {
    name: 'uteach-pool'
    backends: [
      {
        address: 'uteach-dev-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'profile-api-pool'
    backends: [
      {
        address: 'profile-api-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'transcript-submission-pool'
    backends: [
      {
        address: 'transcript-submission-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'educator-licensing-pool'
    backends: [
      {
        address: 'educator-licensing-dev-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'criminal-background-review-pool'
    backends: [
      {
        address: 'criminal-background-review-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'educator-wizard-pool'
    backends: [
      {
        address: 'educator-wizard-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'ethics-review-api-pool'
    backends: [
      {
        address: 'ethics-review-api-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
  {
    name: 'student-registration-pool'
    backends: [
      {
        address: 'student-registration-dev.azurewebsites.net'
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 100
        enabledState: 'Enabled'
      }
    ]
    healthProbeSettings: {
      path: '/.health'
      protocol: 'Https'
      intervalInSeconds: 240
      method: 'GET'
    }
  }
]

@description('URL path maps for routing rules')
param urlPathMaps array = [
  {
    name: 'api-routing-pathmap'
    defaultBackendPool: 'uteach-pool'
    pathRules: [
      {
        name: 'profile-api-rule'
        paths: ['/profile-api/*']
        backendPool: 'profile-api-pool'
      }
      {
        name: 'transcript-submission-rule'
        paths: ['/transcript-submission/*']
        backendPool: 'transcript-submission-pool'
      }
      {
        name: 'educator-licensing-rule'
        paths: ['/educator-licensing-api/*']
        backendPool: 'educator-licensing-pool'
      }
      {
        name: 'criminal-background-rule'
        paths: ['/criminal-background-review-api/*']
        backendPool: 'criminal-background-review-pool'
      }
      {
        name: 'wizard-api-rule'
        paths: ['/wizard-api/*']
        backendPool: 'educator-wizard-pool'
      }
      {
        name: 'ethics-review-rule'
        paths: ['/ethics-review-api/*']
        backendPool: 'ethics-review-api-pool'
      }
      {
        name: 'student-registration-rule'
        paths: ['/student-registration-api/*']
        backendPool: 'student-registration-pool'
      }
    ]
  }
]

@description('Enable diagnostics')
param enableDiagnostics bool = true

@description('Log Analytics workspace resource ID for diagnostics')
param logAnalyticsWorkspaceId string = ''

@description('Enable HTTP to HTTPS redirect')
param enableHttpsRedirect bool = true

@description('Enable caching')
param enableCaching bool = true

@description('Default cache duration in seconds')
param defaultCacheDuration int = 3600

@description('Tags to apply to resources')
param tags object = {
  Environment: environment
  Service: 'FrontDoor'
  Application: 'USIMS'
  CreatedBy: 'Bicep'
}

// ============================================================================
// VARIABLES
// ============================================================================

var frontDoorProfileName = frontDoorName
var frontDoorEndpointName = '${frontDoorName}-endpoint'
var wafPolicyResourceName = replace(wafPolicyName, '-', '')

// Create origin group names from backend pools
var originGroups = [for pool in backendPools: {
  name: replace(pool.name, '-pool', '-origin-group')
  poolName: pool.name
  backends: pool.backends
  healthProbeSettings: pool.healthProbeSettings
}]

// Create route configurations from URL path maps
var routeConfigurations = [for pathMap in urlPathMaps: {
  name: pathMap.name
  defaultOriginGroup: replace(pathMap.defaultBackendPool, '-pool', '-origin-group')
  pathRules: [for rule in pathMap.pathRules: {
    name: rule.name
    paths: rule.paths
    originGroup: replace(rule.backendPool, '-pool', '-origin-group')
  }]
}]

// Security policy configuration
var securityPolicyConfig = {
  wafEnabled: enableWaf
  wafMode: wafMode
  rateLimitThreshold: rateLimitThreshold
  botProtectionEnabled: enableBotProtection
  geoFilteringEnabled: enableGeoFiltering
  allowedCountries: allowedCountries
  customBlockStatusCode: customBlockResponseStatusCode
}

// Caching configuration
var cachingConfig = {
  enabled: enableCaching
  defaultDuration: defaultCacheDuration
  queryStringCachingBehavior: 'IgnoreQueryString'
  compressionEnabled: true
}

// ============================================================================
// Azure Front Door Complete Bicep Template - Part 2
// WAF Policy Resources
// ============================================================================

// WAF Policy Resource
resource wafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2022-05-01' = if (enableWaf) {
  name: wafPolicyResourceName
  location: 'Global'
  tags: tags
  sku: {
    name: frontDoorSku
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: securityPolicyConfig.wafMode
      redirectUrl: null
      customBlockResponseStatusCode: securityPolicyConfig.customBlockStatusCode
      customBlockResponseBody: base64('Access Denied - Request blocked by security policy')
      requestBodyCheck: 'Enabled'
    }
    customRules: {
      rules: concat([
        // Rate limiting rule
        {
          name: 'RateLimitRule'
          priority: 1
          enabledState: 'Enabled'
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: securityPolicyConfig.rateLimitThreshold
          matchConditions: [
            {
              matchVariable: 'RemoteAddr'
              operator: 'IPMatch'
              negateCondition: false
              matchValue: [
                '0.0.0.0/0'
                '::/0'
              ]
            }
          ]
          action: 'Block'
        }
        // Block common SQL injection patterns
        {
          name: 'BlockSQLInjection'
          priority: 2
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'QueryString'
              operator: 'Contains'
              negateCondition: false
              matchValue: [
                'union'
                'select'
                'insert'
                'drop'
                'delete'
                'update'
                'exec'
                'script'
                'declare'
                'cast'
                'convert'
              ]
              transforms: [
                'Lowercase'
                'UrlDecode'
                'RemoveNulls'
              ]
            }
          ]
          action: 'Block'
        }
        // Block XSS attempts
        {
          name: 'BlockXSS'
          priority: 3
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'QueryString'
              operator: 'Contains'
              negateCondition: false
              matchValue: [
                '<script'
                'javascript:'
                'vbscript:'
                'onload='
                'onerror='
                'onclick='
                'alert('
                'document.cookie'
              ]
              transforms: [
                'Lowercase'
                'UrlDecode'
                'HtmlEntityDecode'
                'RemoveNulls'
              ]
            }
          ]
          action: 'Block'
        }
        // Block directory traversal attempts
        {
          name: 'BlockDirectoryTraversal'
          priority: 4
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              negateCondition: false
              matchValue: [
                '../'
                '..%2f'
                '..%5c'
                '%2e%2e%2f'
                '%2e%2e%5c'
              ]
              transforms: [
                'Lowercase'
                'UrlDecode'
              ]
            }
          ]
          action: 'Block'
        }
        // Allow health check endpoints
        {
          name: 'AllowHealthChecks'
          priority: 5
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              negateCondition: false
              matchValue: [
                '/.health'
                '/health'
                '/status'
                '/ping'
                '/heartbeat'
              ]
            }
          ]
          action: 'Allow'
        }
        // Allow ACME challenge for SSL certificates
        {
          name: 'AllowACMEChallenge'
          priority: 6
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'BeginsWith'
              negateCondition: false
              matchValue: [
                '/.well-known/acme-challenge/'
              ]
            }
          ]
          action: 'Allow'
        }
        // Block common attack user agents
        {
          name: 'BlockMaliciousUserAgents'
          priority: 7
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RequestHeader'
              selector: 'User-Agent'
              operator: 'Contains'
              negateCondition: false
              matchValue: [
                'sqlmap'
                'nikto'
                'nessus'
                'burpsuite'
                'masscan'
                'nmap'
                'acunetix'
                'havij'
              ]
              transforms: [
                'Lowercase'
              ]
            }
          ]
          action: 'Block'
        }
        // Block requests without User-Agent
        {
          name: 'BlockEmptyUserAgent'
          priority: 8
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RequestHeader'
              selector: 'User-Agent'
              operator: 'Equal'
              negateCondition: false
              matchValue: [
                ''
              ]
            }
          ]
          action: 'Block'
        }
      ], securityPolicyConfig.geoFilteringEnabled ? [
        // Geo filtering rule (only if enabled)
        {
          name: 'GeoFilteringRule'
          priority: 10
          enabledState: 'Enabled'
          ruleType: 'MatchRule'
          matchConditions: [
            {
              matchVariable: 'RemoteAddr'
              operator: 'GeoMatch'
              negateCondition: true
              matchValue: securityPolicyConfig.allowedCountries
            }
          ]
          action: 'Block'
        }
      ] : [])
    }
    managedRules: {
      managedRuleSets: concat([
        // Default rule set (always included)
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
          exclusions: [
            // Exclude health check endpoints from some rules
            {
              matchVariable: 'RequestUriMatchVariable'
              selectorMatchOperator: 'Contains'
              selector: '/.health'
            }
            {
              matchVariable: 'RequestUriMatchVariable'
              selectorMatchOperator: 'Contains'
              selector: '/status'
            }
          ]
          ruleGroupOverrides: [
            {
              ruleGroupName: 'SQLI'
              rules: [
                {
                  ruleId: '942100'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '942110'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '942120'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '942130'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '942140'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
              ]
            }
            {
              ruleGroupName: 'XSS'
              rules: [
                {
                  ruleId: '941100'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '941110'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '941120'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '941130'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
              ]
            }
            {
              ruleGroupName: 'RFI'
              rules: [
                {
                  ruleId: '931100'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '931110'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
              ]
            }
            {
              ruleGroupName: 'LFI'
              rules: [
                {
                  ruleId: '930100'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '930110'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
              ]
            }
          ]
        }
      ], (frontDoorSku == 'Premium_AzureFrontDoor' && securityPolicyConfig.botProtectionEnabled) ? [
        // Bot Manager rule set (Premium only)
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.0'
          ruleSetAction: 'Block'
          exclusions: []
          ruleGroupOverrides: [
            {
              ruleGroupName: 'BadBots'
              rules: [
                {
                  ruleId: '100100'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
                {
                  ruleId: '100200'
                  enabledState: 'Enabled'
                  action: 'Block'
                }
              ]
            }
            {
              ruleGroupName: 'GoodBots'
              rules: [
                {
                  ruleId: '200100'
                  enabledState: 'Enabled'
                  action: 'Allow'
                }
                {
                  ruleId: '200200'
                  enabledState: 'Enabled'
                  action: 'Allow'
                }
              ]
            }
            {
              ruleGroupName: 'UnknownBots'
              rules: [
                {
                  ruleId: '300100'
                  enabledState: 'Enabled'
                  action: 'Log'
                }
              ]
            }
          ]
        }
      ] : [])
    }
  }
}

// ============================================================================
// END OF PART 2
// ============================================================================
// ============================================================================
// Azure Front Door Complete Bicep Template - Part 3
// Front Door Profile and Endpoint Resources
// ============================================================================

// Front Door Profile Resource
resource frontDoorProfile 'Microsoft.Cdn/profiles@2023-05-01' = {
  name: frontDoorProfileName
  location: 'Global'
  tags: tags
  sku: {
    name: frontDoorSku
  }
  properties: {
    originResponseTimeoutSeconds: 60
  }
}

// Front Door Endpoint Resource
resource frontDoorEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2023-05-01' = {
  parent: frontDoorProfile
  name: frontDoorEndpointName
  location: 'Global'
  tags: tags
  properties: {
    enabledState: 'Enabled'
  }
}

// Security Policy (links WAF to Front Door)
resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2023-05-01' = if (enableWaf) {
  parent: frontDoorProfile
  name: '${frontDoorProfileName}-security-policy'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: {
        id: wafPolicy.id
      }
      associations: [
        {
          domains: [
            {
              id: frontDoorEndpoint.id
            }
          ]
          patternsToMatch: [
            '/*'
          ]
        }
      ]
    }
  }
  dependsOn: [
    wafPolicy
    frontDoorEndpoint
  ]
}

// Rule Set for URL Rewrites and Headers
resource ruleSet 'Microsoft.Cdn/profiles/ruleSets@2023-05-01' = {
  parent: frontDoorProfile
  name: '${frontDoorProfileName}-ruleset'
  properties: {}
  dependsOn: [
    frontDoorProfile
  ]
}

// Security Headers Rule
resource securityHeadersRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = {
  parent: ruleSet
  name: 'SecurityHeaders'
  properties: {
    order: 1
    conditions: []
    actions: [
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-Content-Type-Options'
          value: 'nosniff'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-Frame-Options'
          value: 'DENY'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-XSS-Protection'
          value: '1; mode=block'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Strict-Transport-Security'
          value: 'max-age=31536000; includeSubDomains'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Referrer-Policy'
          value: 'strict-origin-when-cross-origin'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Content-Security-Policy'
          value: 'default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' data:; connect-src \'self\' https:; frame-ancestors \'none\';'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    ruleSet
  ]
}

// HTTPS Redirect Rule
resource httpsRedirectRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = if (enableHttpsRedirect) {
  parent: ruleSet
  name: 'HttpsRedirect'
  properties: {
    order: 2
    conditions: [
      {
        name: 'RequestScheme'
        parameters: {
          typeName: 'DeliveryRuleRequestSchemeConditionParameters'
          operator: 'Equal'
          negateCondition: false
          matchValues: [
            'HTTP'
          ]
          transforms: []
        }
      }
    ]
    actions: [
      {
        name: 'UrlRedirect'
        parameters: {
          typeName: 'DeliveryRuleUrlRedirectActionParameters'
          redirectType: 'PermanentRedirect'
          destinationProtocol: 'Https'
          customPath: null
          customHostname: null
          customQueryString: null
          customFragment: null
        }
      }
    ]
    matchProcessingBehavior: 'Stop'
  }
  dependsOn: [
    securityHeadersRule
  ]
}

// Cache Optimization Rule for Static Content
resource cacheOptimizationRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = if (enableCaching) {
  parent: ruleSet
  name: 'CacheOptimization'
  properties: {
    order: 3
    conditions: [
      {
        name: 'UrlFileExtension'
        parameters: {
          typeName: 'DeliveryRuleUrlFileExtensionMatchConditionParameters'
          operator: 'Equal'
          negateCondition: false
          matchValues: [
            'css'
            'js'
            'png'
            'jpg'
            'jpeg'
            'gif'
            'ico'
            'svg'
            'woff'
            'woff2'
            'ttf'
            'eot'
            'pdf'
          ]
          transforms: [
            'Lowercase'
          ]
        }
      }
    ]
    actions: [
      {
        name: 'CacheExpiration'
        parameters: {
          typeName: 'DeliveryRuleCacheExpirationActionParameters'
          cacheBehavior: 'Override'
          cacheType: 'All'
          cacheDuration: '7.00:00:00'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Cache-Control'
          value: 'public, max-age=604800, immutable'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    httpsRedirectRule
  ]
}

// API Cache Rule (No Cache for API endpoints)
resource apiNoCacheRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = {
  parent: ruleSet
  name: 'ApiNoCache'
  properties: {
    order: 4
    conditions: [
      {
        name: 'UrlPath'
        parameters: {
          typeName: 'DeliveryRuleUrlPathMatchConditionParameters'
          operator: 'BeginsWith'
          negateCondition: false
          matchValues: [
            '/profile-api/'
            '/transcript-submission/'
            '/educator-licensing-api/'
            '/criminal-background-review-api/'
            '/wizard-api/'
            '/ethics-review-api/'
            '/student-registration-api/'
          ]
          transforms: [
            'Lowercase'
          ]
        }
      }
    ]
    actions: [
      {
        name: 'CacheExpiration'
        parameters: {
          typeName: 'DeliveryRuleCacheExpirationActionParameters'
          cacheBehavior: 'BypassCache'
          cacheType: 'All'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Cache-Control'
          value: 'no-cache, no-store, must-revalidate'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    cacheOptimizationRule
  ]
}

// Health Check Allow Rule
resource healthCheckRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = {
  parent: ruleSet
  name: 'HealthCheckAllow'
  properties: {
    order: 5
    conditions: [
      {
        name: 'UrlPath'
        parameters: {
          typeName: 'DeliveryRuleUrlPathMatchConditionParameters'
          operator: 'Equal'
          negateCondition: false
          matchValues: [
            '/.health'
            '/health'
            '/status'
            '/ping'
            '/heartbeat'
          ]
          transforms: [
            'Lowercase'
          ]
        }
      }
    ]
    actions: [
      {
        name: 'CacheExpiration'
        parameters: {
          typeName: 'DeliveryRuleCacheExpirationActionParameters'
          cacheBehavior: 'BypassCache'
          cacheType: 'All'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-Health-Check'
          value: 'allowed'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    apiNoCacheRule
  ]
}

// Compression Rule
resource compressionRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = {
  parent: ruleSet
  name: 'EnableCompression'
  properties: {
    order: 6
    conditions: [
      {
        name: 'RequestHeader'
        parameters: {
          typeName: 'DeliveryRuleRequestHeaderConditionParameters'
          selector: 'Accept-Encoding'
          operator: 'Contains'
          negateCondition: false
          matchValues: [
            'gzip'
            'deflate'
            'br'
          ]
          transforms: [
            'Lowercase'
          ]
        }
      }
    ]
    actions: [
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Vary'
          value: 'Accept-Encoding'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    healthCheckRule
  ]
}

// ============================================================================
// END OF PART 3
// ============================================================================


// ============================================================================
// Azure Front Door Complete Bicep Template - Part 5
// Custom Domains and SSL Certificates
// ============================================================================

// Custom Domains
resource customDomainResources 'Microsoft.Cdn/profiles/customDomains@2023-05-01' = [for (domain, index) in customDomains: if (enableCustomDomains) {
  parent: frontDoorProfile
  name: replace(domain.name, '.', '-')
  properties: {
    hostName: domain.hostName
    tlsSettings: {
      certificateType: domain.certificateType
      minimumTlsVersion: 'TLS12'
    }
    azureDnsZone: null
    preValidatedCustomDomainResourceId: null
  }
  dependsOn: [
    frontDoorProfile
  ]
}]

// Primary Custom Domain (usims.usims-dev.schools.utah.gov)
resource primaryCustomDomain 'Microsoft.Cdn/profiles/customDomains@2023-05-01' = if (enableCustomDomains) {
  parent: frontDoorProfile
  name: 'primary-domain'
  properties: {
    hostName: 'usims.usims-dev.schools.utah.gov'
    tlsSettings: {
      certificateType: 'ManagedCertificate'
      minimumTlsVersion: 'TLS12'
    }
    azureDnsZone: null
    preValidatedCustomDomainResourceId: null
  }
  dependsOn: [
    frontDoorProfile
  ]
}

// Secondary Custom Domain (qa.usims-dev.schools.utah.gov)
resource secondaryCustomDomain 'Microsoft.Cdn/profiles/customDomains@2023-05-01' = if (enableCustomDomains) {
  parent: frontDoorProfile
  name: 'secondary-domain'
  properties: {
    hostName: 'qa.usims-dev.schools.utah.gov'
    tlsSettings: {
      certificateType: 'ManagedCertificate'
      minimumTlsVersion: 'TLS12'
    }
    azureDnsZone: null
    preValidatedCustomDomainResourceId: null
  }
  dependsOn: [
    frontDoorProfile
  ]
}

// Domain Validation Configuration
var domainValidationConfig = {
  validationMethod: 'dns-txt-token'
  autoRotateEnabled: true
  certificateAuthority: 'DigiCert'
  validationTimeoutInMinutes: 30
}

// SSL/TLS Configuration
var tlsConfiguration = {
  minimumTlsVersion: 'TLS12'
  cipherSuite: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256'
  protocols: ['TLSv1.2', 'TLSv1.3']
  certificateSource: 'AzureKeyVault'
  sniEnabled: true
}

// Certificate Management Settings
var certificateSettings = {
  autoRenewalEnabled: true
  renewalThresholdDays: 30
  keySize: 2048
  signatureAlgorithm: 'SHA256'
  extendedValidation: false
}

// Domain Association with Endpoint
resource domainAssociations 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = [for (domain, index) in customDomains: if (enableCustomDomains) {
  parent: frontDoorEndpoint
  name: '${domain.name}-association'
  properties: {
    customDomains: [
      {
        id: customDomainResources[index].id
      }
    ]
    originGroup: {
      id: originGroups[0].id
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    customDomainResources
    originGroups
    ruleSet
  ]
}]

// Primary Domain Route Configuration
resource primaryDomainRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = if (enableCustomDomains) {
  parent: frontDoorEndpoint
  name: 'primary-domain-route'
  properties: {
    customDomains: [
      {
        id: primaryCustomDomain.id
      }
    ]
    originGroup: {
      id: originGroups[0].id
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        contentTypesToCompress: [
          'application/eot'
          'application/font'
          'application/font-sfnt'
          'application/javascript'
          'application/json'
          'application/opentype'
          'application/otf'
          'application/pkcs7-mime'
          'application/truetype'
          'application/ttf'
          'application/vnd.ms-fontobject'
          'application/xhtml+xml'
          'application/xml'
          'application/xml+rss'
          'application/x-font-opentype'
          'application/x-font-truetype'
          'application/x-font-ttf'
          'application/x-httpd-cgi'
          'application/x-javascript'
          'application/x-mpegurl'
          'application/x-opentype'
          'application/x-otf'
          'application/x-perl'
          'application/x-ttf'
          'font/eot'
          'font/ttf'
          'font/otf'
          'font/opentype'
          'image/svg+xml'
          'text/css'
          'text/csv'
          'text/html'
          'text/javascript'
          'text/js'
          'text/plain'
          'text/richtext'
          'text/tab-separated-values'
          'text/xml'
          'text/x-script'
          'text/x-component'
          'text/x-java-source'
        ]
        isCompressionEnabled: true
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    primaryCustomDomain
    originGroups
    ruleSet
  ]
}

// Secondary Domain Route Configuration
resource secondaryDomainRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = if (enableCustomDomains) {
  parent: frontDoorEndpoint
  name: 'secondary-domain-route'
  properties: {
    customDomains: [
      {
        id: secondaryCustomDomain.id
      }
    ]
    originGroup: {
      id: originGroups[0].id
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        contentTypesToCompress: [
          'text/css'
          'text/html'
          'text/javascript'
          'application/javascript'
          'application/json'
          'application/xml'
          'text/xml'
          'image/svg+xml'
        ]
        isCompressionEnabled: true
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    secondaryCustomDomain
    originGroups
    ruleSet
  ]
}

// Domain Validation Rules for ACME Challenge
resource acmeChallengeRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = if (enableCustomDomains) {
  parent: ruleSet
  name: 'AcmeChallengeRule'
  properties: {
    order: 0
    conditions: [
      {
        name: 'UrlPath'
        parameters: {
          typeName: 'DeliveryRuleUrlPathMatchConditionParameters'
          operator: 'BeginsWith'
          negateCondition: false
          matchValues: [
            '/.well-known/acme-challenge/'
          ]
          transforms: []
        }
      }
    ]
    actions: [
      {
        name: 'CacheExpiration'
        parameters: {
          typeName: 'DeliveryRuleCacheExpirationActionParameters'
          cacheBehavior: 'BypassCache'
          cacheType: 'All'
        }
      }
      {
        name: 'RouteConfigurationOverride'
        parameters: {
          typeName: 'DeliveryRuleRouteConfigurationOverrideActionParameters'
          originGroupOverride: {
            originGroup: {
              id: originGroups[0].id
            }
            forwardingProtocol: 'HttpOnly'
          }
        }
      }
    ]
    matchProcessingBehavior: 'Stop'
  }
  dependsOn: [
    ruleSet
    originGroups
  ]
}

// SSL Certificate Monitoring
var sslMonitoringConfig = {
  certificateExpiryWarningDays: 30
  certificateExpiryAlertDays: 7
  enableCertificateHealthCheck: true
  certificateValidationInterval: 'PT24H'
}

// Domain Security Headers
resource domainSecurityRule 'Microsoft.Cdn/profiles/ruleSets/rules@2023-05-01' = if (enableCustomDomains) {
  parent: ruleSet
  name: 'DomainSecurityHeaders'
  properties: {
    order: 1
    conditions: [
      {
        name: 'RequestScheme'
        parameters: {
          typeName: 'DeliveryRuleRequestSchemeConditionParameters'
          operator: 'Equal'
          negateCondition: false
          matchValues: [
            'HTTPS'
          ]
          transforms: []
        }
      }
    ]
    actions: [
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'Strict-Transport-Security'
          value: 'max-age=31536000; includeSubDomains; preload'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-Content-Type-Options'
          value: 'nosniff'
        }
      }
      {
        name: 'ModifyResponseHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Append'
          headerName: 'X-Frame-Options'
          value: 'SAMEORIGIN'
        }
      }
    ]
    matchProcessingBehavior: 'Continue'
  }
  dependsOn: [
    acmeChallengeRule
  ]
}

// Certificate Auto-Renewal Configuration
var autoRenewalSettings = {
  enabled: true
  renewBeforeExpiryDays: 30
  notificationEmails: []
  keyVaultSettings: {
    secretName: '${frontDoorName}-ssl-cert'
    vaultUri: ''
    certificateName: '${frontDoorName}-certificate'
  }
}

// ============================================================================
// END OF PART 5
// ============================================================================
// ============================================================================
// Azure Front Door Complete Bicep Template - Part 6A
// Routes and Routing Rules (First Half)
// ============================================================================

// Default Route (Main Application - uteach)
resource defaultRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'default-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[0].id // uteach-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        isCompressionEnabled: enableCaching
        contentTypesToCompress: [
          'text/html'
          'text/css'
          'text/javascript'
          'application/javascript'
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Profile API Route
resource profileApiRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'profile-api-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[1].id // profile-api-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/profile-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'UseQueryString'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
          'application/xml'
          'text/xml'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Transcript Submission Route
resource transcriptSubmissionRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'transcript-submission-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[2].id // transcript-submission-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/transcript-submission/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
          'application/xml'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Educator Licensing Route
resource educatorLicensingRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'educator-licensing-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[3].id // educator-licensing-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/educator-licensing-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Criminal Background Review Route
resource criminalBackgroundRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'criminal-background-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[4].id // criminal-background-review-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/criminal-background-review-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// ============================================================================
// END OF PART 6A
// ============================================================================
// ============================================================================
// Azure Front Door Complete Bicep Template - Part 6B
// Routes and Routing Rules (Second Half)
// ============================================================================

// Educator Wizard Route
resource educatorWizardRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'educator-wizard-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[5].id // educator-wizard-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/wizard-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Ethics Review API Route
resource ethicsReviewRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'ethics-review-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[6].id // ethics-review-api-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/ethics-review-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Student Registration Route
resource studentRegistrationRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'student-registration-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[7].id // student-registration-origin-group
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/student-registration-api/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'application/json'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Health Check Route (Special handling)
resource healthCheckRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'health-check-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[0].id // Default to main app
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/.health'
      '/health'
      '/status'
      '/ping'
      '/heartbeat'
    ]
    forwardingProtocol: 'MatchRequest'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Disabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'BypassCache'
      compressionSettings: {
        isCompressionEnabled: false
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Static Assets Route (CSS, JS, Images)
resource staticAssetsRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: frontDoorEndpoint
  name: 'static-assets-route'
  properties: {
    customDomains: enableCustomDomains ? [
      {
        id: primaryCustomDomain.id
      }
      {
        id: secondaryCustomDomain.id
      }
    ] : []
    originGroup: {
      id: originGroups[0].id // Main app serves static content
    }
    supportedProtocols: [
      'Http'
      'Https'
    ]
    patternsToMatch: [
      '/css/*'
      '/js/*'
      '/images/*'
      '/fonts/*'
      '/assets/*'
      '*.css'
      '*.js'
      '*.png'
      '*.jpg'
      '*.jpeg'
      '*.gif'
      '*.ico'
      '*.svg'
      '*.woff'
      '*.woff2'
      '*.ttf'
      '*.eot'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        isCompressionEnabled: true
        contentTypesToCompress: [
          'text/css'
          'text/javascript'
          'application/javascript'
          'image/svg+xml'
          'application/font-woff'
          'application/font-woff2'
        ]
      }
    }
    ruleSets: [
      {
        id: ruleSet.id
      }
    ]
  }
  dependsOn: [
    frontDoorEndpoint
    originGroups
    ruleSet
  ]
}

// Route Priority Configuration
var routePriorities = {
  healthCheck: 1
  staticAssets: 2
  profileApi: 3
  transcriptSubmission: 4
  educatorLicensing: 5
  criminalBackground: 6
  educatorWizard: 7
  ethicsReview: 8
  studentRegistration: 9
  default: 10
}

// Route Caching Strategies
var cachingStrategies = {
  staticContent: {
    queryStringCachingBehavior: 'IgnoreQueryString'
    cacheDuration: '7.00:00:00'
    compressionEnabled: true
  }
  apiContent: {
    queryStringCachingBehavior: 'BypassCache'
    cacheDuration: '00:00:00'
    compressionEnabled: true
  }
  dynamicContent: {
    queryStringCachingBehavior: 'UseQueryString'
    cacheDuration: '00:05:00'
    compressionEnabled: true
  }
  healthChecks: {
    queryStringCachingBehavior: 'BypassCache'
    cacheDuration: '00:00:00'
    compressionEnabled: false
  }
}

// Route Matching Patterns
var routePatterns = {
  apis: [
    '/profile-api/*'
    '/transcript-submission/*'
    '/educator-licensing-api/*'
    '/criminal-background-review-api/*'
    '/wizard-api/*'
    '/ethics-review-api/*'
    '/student-registration-api/*'
  ]
  staticAssets: [
    '/css/*'
    '/js/*'
    '/images/*'
    '/fonts/*'
    '/assets/*'
    '*.css'
    '*.js'
    '*.png'
    '*.jpg'
    '*.jpeg'
    '*.gif'
    '*.ico'
    '*.svg'
    '*.woff'
    '*.woff2'
    '*.ttf'
    '*.eot'
    '*.pdf'
  ]
  healthChecks: [
    '/.health'
    '/health'
    '/status'
    '/ping'
    '/heartbeat'
  ]
  default: [
    '/*'
  ]
}

// Route Security Configuration
var routeSecurityConfig = {
  httpsOnly: true
  httpsRedirect: true
  minimumTlsVersion: 'TLS12'
  certificateValidation: true
  hostnameValidation: true
}

// Route Performance Configuration
var routePerformanceConfig = {
  compressionEnabled: true
  cachingEnabled: enableCaching
  originTimeout: 60
  keepAliveTimeout: 30
  connectionPooling: true
}

// ============================================================================
// END OF PART 6B
// ============================================================================
// ============================================================================
// Azure Front Door Complete Bicep Template - Part 7
// Monitoring and Diagnostics
// ============================================================================

// Log Analytics Workspace for Front Door
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = if (enableMonitoring) {
  name: '${frontDoorName}-logs'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: logRetentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      disableLocalAuth: false
    }
    workspaceCapping: {
      dailyQuotaGb: 10
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Application Insights for Front Door
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = if (enableMonitoring) {
  name: '${frontDoorName}-insights'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    RetentionInDays: logRetentionDays
  }
  dependsOn: [
    logAnalyticsWorkspace
  ]
}

// Diagnostic Settings for Front Door Profile
resource frontDoorDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableMonitoring) {
  name: '${frontDoorName}-diagnostics'
  scope: frontDoorProfile
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: logRetentionDays
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: logRetentionDays
        }
      }
    ]
  }
  dependsOn: [
    frontDoorProfile
    logAnalyticsWorkspace
  ]
}

// Diagnostic Settings for WAF Policy
resource wafDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableWaf && enableMonitoring) {
  name: '${wafPolicyName}-diagnostics'
  scope: wafPolicy
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: logRetentionDays
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: logRetentionDays
        }
      }
    ]
  }
  dependsOn: [
    wafPolicy
    logAnalyticsWorkspace
  ]
}

// Action Group for Alerts
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-alerts'
  location: 'Global'
  tags: tags
  properties: {
    groupShortName: 'FD-Alerts'
    enabled: true
    emailReceivers: [
      {
        name: 'AdminEmail'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
    smsReceivers: []
    webhookReceivers: []
    eventHubReceivers: []
    itsmReceivers: []
    azureAppPushReceivers: []
    automationRunbookReceivers: []
    voiceReceivers: []
    logicAppReceivers: []
    azureFunctionReceivers: []
    armRoleReceivers: [
      {
        name: 'Monitoring Contributor'
        roleId: '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
        useCommonAlertSchema: true
      }
    ]
  }
}

// High Error Rate Alert
resource highErrorRateAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-high-error-rate'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when Front Door error rate exceeds 5%'
    severity: 2
    enabled: true
    scopes: [
      frontDoorProfile.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighErrorRate'
          metricName: 'Percentage4XX'
          metricNamespace: 'Microsoft.Cdn/profiles'
          operator: 'GreaterThan'
          threshold: 5
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
  dependsOn: [
    frontDoorProfile
    actionGroup
  ]
}

// High Latency Alert
resource highLatencyAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-high-latency'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when Front Door response time exceeds 2 seconds'
    severity: 3
    enabled: true
    scopes: [
      frontDoorProfile.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighLatency'
          metricName: 'TotalLatency'
          metricNamespace: 'Microsoft.Cdn/profiles'
          operator: 'GreaterThan'
          threshold: 2000
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
  dependsOn: [
    frontDoorProfile
    actionGroup
  ]
}

// WAF Blocked Requests Alert
resource wafBlockedAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableWaf && enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-waf-blocked'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when WAF blocks more than 100 requests in 15 minutes'
    severity: 2
    enabled: true
    scopes: [
      wafPolicy.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'WAFBlocked'
          metricName: 'WebApplicationFirewallRequestCount'
          metricNamespace: 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies'
          operator: 'GreaterThan'
          threshold: 100
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'Action'
              operator: 'Include'
              values: [
                'Block'
              ]
            }
          ]
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
  dependsOn: [
    wafPolicy
    actionGroup
  ]
}

// Origin Health Alert
resource originHealthAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-origin-health'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when origin health percentage drops below 80%'
    severity: 1
    enabled: true
    scopes: [
      frontDoorProfile.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'OriginHealth'
          metricName: 'OriginHealthPercentage'
          metricNamespace: 'Microsoft.Cdn/profiles'
          operator: 'LessThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
  dependsOn: [
    frontDoorProfile
    actionGroup
  ]
}

// Cache Hit Ratio Alert
resource cacheHitRatioAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableCaching && enableMonitoring && enableAlerting) {
  name: '${frontDoorName}-cache-hit-ratio'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when cache hit ratio drops below 70%'
    severity: 3
    enabled: true
    scopes: [
      frontDoorProfile.id
    ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'CacheHitRatio'
          metricName: 'CacheHitRatio'
          metricNamespace: 'Microsoft.Cdn/profiles'
          operator: 'LessThan'
          threshold: 70
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
  dependsOn: [
    frontDoorProfile
    actionGroup
  ]
}

// Custom Log Analytics Queries
var logAnalyticsQueries = [
  {
    name: 'Top Error Pages'
    query: 'AzureDiagnostics | where Category == "FrontdoorAccessLog" | where httpStatusCode_d >= 400 | summarize count() by requestUri_s, httpStatusCode_d | order by count_ desc | take 10'
    description: 'Shows the top 10 pages generating errors'
  }
  {
    name: 'Geographic Traffic Distribution'
    query: 'AzureDiagnostics | where Category == "FrontdoorAccessLog" | summarize count() by clientCountry_s | order by count_ desc'
    description: 'Shows traffic distribution by country'
  }
  {
    name: 'WAF Blocked Requests'
    query: 'AzureDiagnostics | where Category == "FrontdoorWebApplicationFirewallLog" | where action_s == "Block" | summarize count() by ruleName_s, clientIP_s | order by count_ desc'
    description: 'Shows blocked requests by WAF rule and client IP'
  }
  {
    name: 'Cache Performance'
    query: 'AzureDiagnostics | where Category == "FrontdoorAccessLog" | summarize HitCount = countif(cacheStatus_s == "HIT"), MissCount = countif(cacheStatus_s == "MISS") | extend HitRatio = (HitCount * 100.0) / (HitCount + MissCount)'
    description: 'Shows cache hit ratio performance'
  }
  {
    name: 'Origin Response Times'
    query: 'AzureDiagnostics | where Category == "FrontdoorAccessLog" | summarize avg(originResponseTime_d), max(originResponseTime_d), min(originResponseTime_d) by bin(TimeGenerated, 5m) | order by TimeGenerated desc'
    description: 'Shows origin response time trends'
  }
]

// Monitoring Dashboard Configuration
var dashboardConfig = {
  name: '${frontDoorName}-dashboard'
  timeRange: 'PT24H'
  refreshInterval: 'PT5M'
  widgets: [
    'RequestCount'
    'ErrorRate'
    'Latency'
    'CacheHitRatio'
    'OriginHealth'
    'WAFBlocked'
    'GeographicDistribution'
    'TopErrors'
  ]
}

// Performance Monitoring Configuration
var performanceMonitoring = {
  enableRealUserMonitoring: true
  enableSyntheticMonitoring: true
  syntheticTestFrequency: 'PT5M'
  syntheticTestLocations: [
    'us-west-2'
    'us-east-1'
    'europe-west'
    'asia-southeast'
  ]
  performanceThresholds: {
    responseTime: 2000
    availability: 99.9
    errorRate: 1.0
  }
}

// Security Monitoring Configuration
var securityMonitoring = {
  enableThreatDetection: true
  enableAnomalyDetection: true
  wafAlertThresholds: {
    blockedRequests: 100
    suspiciousActivity: 50
    rateLimitExceeded: 200
  }
  securityIncidentResponse: {
    autoBlock: false
    notificationDelay: 'PT5M'
    escalationThreshold: 500
  }
}

// ============================================================================
// END OF PART 7
// ============================================================================
// ============================================================================
// Azure Front Door Complete Bicep Template - Part 9
// Outputs and Final Configuration
// ============================================================================

// Primary Outputs - Essential Information
output frontDoorEndpointHostname string = frontDoorEndpoint.properties.hostName
output frontDoorId string = frontDoorProfile.id
output frontDoorName string = frontDoorProfile.name
output frontDoorEndpointId string = frontDoorEndpoint.id

// Custom Domain Outputs
output primaryCustomDomainId string = enableCustomDomains ? primaryCustomDomain.id : ''
output secondaryCustomDomainId string = enableCustomDomains ? secondaryCustomDomain.id : ''
output primaryCustomDomainValidationToken string = enableCustomDomains ? primaryCustomDomain.properties.validationProperties.validationToken : ''
output secondaryCustomDomainValidationToken string = enableCustomDomains ? secondaryCustomDomain.properties.validationProperties.validationToken : ''

// SSL Certificate Outputs
output primaryCertificateId string = enableCustomDomains ? primaryManagedCertificate.id : ''
output secondaryCertificateId string = enableCustomDomains ? secondaryManagedCertificate.id : ''

// WAF Policy Outputs
output wafPolicyId string = enableWaf ? wafPolicy.id : ''
output wafPolicyName string = enableWaf ? wafPolicy.name : ''
output wafPolicyResourceId string = enableWaf ? wafPolicy.id : ''

// Origin Group Outputs
output originGroupIds array = [for i in range(0, length(originConfigs)): originGroups[i].id]
output originGroupNames array = [for i in range(0, length(originConfigs)): originGroups[i].name]

// Individual Origin Group IDs for easy reference
output uteachOriginGroupId string = originGroups[0].id
output profileApiOriginGroupId string = originGroups[1].id
output transcriptSubmissionOriginGroupId string = originGroups[2].id
output educatorLicensingOriginGroupId string = originGroups[3].id
output criminalBackgroundOriginGroupId string = originGroups[4].id
output educatorWizardOriginGroupId string = originGroups[5].id
output ethicsReviewOriginGroupId string = originGroups[6].id
output studentRegistrationOriginGroupId string = originGroups[7].id

// Route Outputs
output defaultRouteId string = defaultRoute.id
output profileApiRouteId string = profileApiRoute.id
output transcriptSubmissionRouteId string = transcriptSubmissionRoute.id
output educatorLicensingRouteId string = educatorLicensingRoute.id
output criminalBackgroundRouteId string = criminalBackgroundRoute.id
output educatorWizardRouteId string = educatorWizardRoute.id
output ethicsReviewRouteId string = ethicsReviewRoute.id
output studentRegistrationRouteId string = studentRegistrationRoute.id

// Rule Set Outputs
output ruleSetId string = ruleSet.id
output ruleSetName string = ruleSet.name

// Monitoring Outputs
output logAnalyticsWorkspaceId string = enableMonitoring ? logAnalyticsWorkspace.id : ''
output applicationInsightsId string = enableMonitoring ? applicationInsights.id : ''
output applicationInsightsInstrumentationKey string = enableMonitoring ? applicationInsights.properties.InstrumentationKey : ''
output applicationInsightsConnectionString string = enableMonitoring ? applicationInsights.properties.ConnectionString : ''

// Alert Outputs
output actionGroupId string = (enableMonitoring && enableAlerting) ? actionGroup.id : ''
output highErrorRateAlertId string = (enableMonitoring && enableAlerting) ? highErrorRateAlert.id : ''
output highLatencyAlertId string = (enableMonitoring && enableAlerting) ? highLatencyAlert.id : ''
output originHealthAlertId string = (enableMonitoring && enableAlerting) ? originHealthAlert.id : ''

// Configuration Summary Outputs
output configurationSummary object = {
  frontDoor: {
    name: frontDoorProfile.name
    sku: frontDoorSku
    endpoint: frontDoorEndpoint.properties.hostName
    customDomainsEnabled: enableCustomDomains
    wafEnabled: enableWaf
    cachingEnabled: enableCaching
  }
  origins: {
    count: length(originConfigs)
    healthProbesEnabled: enableHealthProbes
    configurations: [for (config, i) in originConfigs: {
      name: config.name
      hostname: config.hostName
      httpPort: config.httpPort
      httpsPort: config.httpsPort
      priority: config.priority
      weight: config.weight
    }]
  }
  security: {
    wafEnabled: enableWaf
    wafMode: enableWaf ? wafPolicyMode : 'Disabled'
    customRulesCount: enableWaf ? length(wafCustomRules) : 0
    managedRulesEnabled: enableWaf
  }
  monitoring: {
    enabled: enableMonitoring
    alertingEnabled: enableAlerting
    logRetentionDays: logRetentionDays
    logAnalyticsEnabled: enableMonitoring
    applicationInsightsEnabled: enableMonitoring
  }
}

// Deployment Information
output deploymentInfo object = {
  timestamp: utcNow()
  location: location
  resourceGroupName: resourceGroup().name
  subscriptionId: subscription().subscriptionId
  deploymentName: deployment().name
  templateVersion: '1.0.0'
  bicepVersion: '0.24.24'
}

// DNS Configuration Instructions
output dnsConfigurationInstructions object = enableCustomDomains ? {
  primaryDomain: {
    domain: primaryCustomDomainName
    recordType: 'CNAME'
    recordName: '@'
    recordValue: frontDoorEndpoint.properties.hostName
    validationToken: primaryCustomDomain.properties.validationProperties.validationToken
    validationRecord: {
      type: 'TXT'
      name: '_dnsauth'
      value: primaryCustomDomain.properties.validationProperties.validationToken
    }
  }
  secondaryDomain: {
    domain: secondaryCustomDomainName
    recordType: 'CNAME'
    recordName: '@'
    recordValue: frontDoorEndpoint.properties.hostName
    validationToken: secondaryCustomDomain.properties.validationProperties.validationToken
    validationRecord: {
      type: 'TXT'
      name: '_dnsauth'
      value: secondaryCustomDomain.properties.validationProperties.validationToken
    }
  }
} : {}

// Health Check Endpoints
output healthCheckEndpoints array = [
  'https://${frontDoorEndpoint.properties.hostName}/.health'
  'https://${frontDoorEndpoint.properties.hostName}/health'
  'https://${frontDoorEndpoint.properties.hostName}/status'
]

// API Endpoints
output apiEndpoints object = {
  profileApi: 'https://${frontDoorEndpoint.properties.hostName}/profile-api'
  transcriptSubmission: 'https://${frontDoorEndpoint.properties.hostName}/transcript-submission'
  educatorLicensing: 'https://${frontDoorEndpoint.properties.hostName}/educator-licensing-api'
  criminalBackground: 'https://${frontDoorEndpoint.properties.hostName}/criminal-background-review-api'
  educatorWizard: 'https://${frontDoorEndpoint.properties.hostName}/wizard-api'
  ethicsReview: 'https://${frontDoorEndpoint.properties.hostName}/ethics-review-api'
  studentRegistration: 'https://${frontDoorEndpoint.properties.hostName}/student-registration-api'
}

// Performance Metrics Endpoints
output performanceMetrics object = enableMonitoring ? {
  logAnalyticsWorkspace: logAnalyticsWorkspace.properties.customerId
  applicationInsights: applicationInsights.properties.AppId
  dashboardUrl: 'https://portal.azure.com/#@${tenant().tenantId}/dashboard/arm${subscription().id}/resourcegroups/${resourceGroup().name}/providers/microsoft.insights/components/${applicationInsights.name}'
  metricsUrl: 'https://portal.azure.com/#@${tenant().tenantId}/resource${frontDoorProfile.id}/metrics'
} : {}

// Security Information
output securityInfo object = enableWaf ? {
  wafPolicyId: wafPolicy.id
  wafPolicyMode: wafPolicyMode
  wafPolicyState: 'Enabled'
  managedRuleSetVersion: '1.0'
  customRulesCount: length(wafCustomRules)
  securityHeaders: [
    'Strict-Transport-Security'
    'X-Content-Type-Options'
    'X-Frame-Options'
    'X-XSS-Protection'
    'Referrer-Policy'
    'Content-Security-Policy'
  ]
} : {
  wafEnabled: false
  securityHeaders: []
}

// Cost Optimization Information
output costOptimization object = {
  sku: frontDoorSku
  cachingEnabled: enableCaching
  compressionEnabled: true
  estimatedMonthlyCost: frontDoorSku == 'Standard_AzureFrontDoor' ? 'Low' : 'Medium'
  costSavingFeatures: [
    enableCaching ? 'Caching Enabled' : 'Caching Disabled'
    'Compression Enabled'
    'Geographic Routing'
    enableHealthProbes ? 'Health Probes Enabled' : 'Health Probes Disabled'
  ]
}

// Troubleshooting Information
output troubleshootingInfo object = {
  commonIssues: [
    {
      issue: 'Custom domain not working'
      solution: 'Verify DNS CNAME record points to ${frontDoorEndpoint.properties.hostName}'
    }
    {
      issue: 'SSL certificate issues'
      solution: 'Ensure domain validation is complete and TXT record is added'
    }
    {
      issue: 'Origin health failures'
      solution: 'Check origin server availability and health probe configuration'
    }
    {
      issue: 'WAF blocking legitimate traffic'
      solution: 'Review WAF logs and adjust custom rules or exclusions'
    }
  ]
  supportResources: [
    'https://docs.microsoft.com/en-us/azure/frontdoor/'
    'https://docs.microsoft.com/en-us/azure/web-application-firewall/afds/'
  ]
}

// Next Steps
output nextSteps array = [
  enableCustomDomains ? 'Configure DNS records for custom domains' : 'Consider adding custom domains'
  'Monitor performance metrics and adjust caching rules'
  'Review WAF logs and fine-tune security rules'
  'Set up additional monitoring alerts as needed'
  'Test failover scenarios with origin groups'
  'Optimize cache hit ratios for better performance'
  'Review and update SSL certificate settings'
  'Configure additional routing rules if needed'
]

// Resource Tags Summary
output resourceTags object = tags

// Compliance and Governance
output complianceInfo object = {
  dataResidency: location
  encryptionInTransit: 'TLS 1.2+'
  encryptionAtRest: 'Azure Managed Keys'
  accessLogging: enableMonitoring
  securityMonitoring: enableWaf
  backupStrategy: 'Multi-origin redundancy'
  disasterRecovery: 'Geographic distribution'
}

// ============================================================================
// END OF PART 9 - TEMPLATE COMPLETE
// ============================================================================
