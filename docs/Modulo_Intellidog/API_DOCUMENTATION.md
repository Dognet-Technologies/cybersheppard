# Intellidog API Documentation

## Overview

Complete REST API documentation for Intellidog threat intelligence module.

**Base URL**: `https://cybersheppard.yourdomain.com/api`  
**API Version**: v1  
**Authentication**: JWT Bearer Token  
**Content-Type**: `application/json`  
**OpenAPI Version**: 3.0.3

---

## Complete OpenAPI 3.0.3 Specification

```yaml
openapi: 3.0.3
info:
  title: Intellidog Threat Intelligence API
  version: 1.0.0
  description: |
    REST API for Intellidog threat intelligence module integrated into CyberSheppard.
    
    **Features**:
    - License management
    - Threat intelligence feeds (MISP, OTX, CSV, JSON)
    - IOC (Indicators of Compromise) management
    - Threat detection correlation
    - Virtual patch auto-generation
    - Threat hunting queries
    
    **Authentication**: JWT Bearer Token required for all endpoints.
    **License**: Valid Intellidog license required for all `/intellidog/*` endpoints.
    
  contact:
    name: Dognet Technologies Support
    email: support@dognet.tech
    url: https://docs.dognet.tech/intellidog
  
  license:
    name: Proprietary
    url: https://dognet.tech/license

servers:
  - url: https://cybersheppard.yourdomain.com/api
    description: Production server
  - url: https://localhost:8000/api
    description: Local development

security:
  - BearerAuth: []

tags:
  - name: License
    description: License management and validation
  - name: Feeds
    description: Threat intelligence feed management
  - name: IOCs
    description: Indicators of Compromise
  - name: Detections
    description: Threat detections and correlation
  - name: Virtual Patches
    description: Auto-generated firewall rules
  - name: Hunting
    description: Threat hunting queries and execution

paths:
  # ========================================================================
  # LICENSE ENDPOINTS
  # ========================================================================
  /intellidog/license/upload:
    post:
      tags: [License]
      summary: Upload license file
      description: Upload and validate Intellidog .lic file with GPG signature
      operationId: uploadLicense
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required: [file]
              properties:
                file:
                  type: string
                  format: binary
                  description: License file (.lic) with GPG signature
      responses:
        '200':
          description: License uploaded and validated successfully
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/License'
        '400':
          $ref: '#/components/responses/ValidationError'
        '401':
          $ref: '#/components/responses/Unauthorized'
  
  /intellidog/license/current:
    get:
      tags: [License]
      summary: Get current license
      description: Retrieve active license information
      operationId: getCurrentLicense
      responses:
        '200':
          description: Current license information
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/License'
        '404':
          $ref: '#/components/responses/NotFound'
  
  /intellidog/license/validate:
    post:
      tags: [License]
      summary: Validate current license
      description: Re-validate active license (manual trigger)
      operationId: validateLicense
      responses:
        '200':
          description: Validation result
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          valid:
                            type: boolean
                          errors:
                            type: array
                            items:
                              type: string
                          warnings:
                            type: array
                            items:
                              type: string
  
  # ========================================================================
  # FEEDS ENDPOINTS
  # ========================================================================
  /intellidog/feeds:
    get:
      tags: [Feeds]
      summary: List feeds
      description: Retrieve all threat intelligence feeds with optional filters
      operationId: listFeeds
      parameters:
        - name: feed_type
          in: query
          schema:
            $ref: '#/components/schemas/FeedType'
        - name: is_active
          in: query
          schema:
            type: boolean
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/PerPage'
      responses:
        '200':
          description: List of feeds
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          feeds:
                            type: array
                            items:
                              $ref: '#/components/schemas/Feed'
                          pagination:
                            $ref: '#/components/schemas/Pagination'
    
    post:
      tags: [Feeds]
      summary: Create feed
      description: Add new threat intelligence feed
      operationId: createFeed
      security:
        - BearerAuth: [admin]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/FeedCreate'
      responses:
        '201':
          description: Feed created successfully
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/Feed'
        '400':
          $ref: '#/components/responses/ValidationError'
        '403':
          $ref: '#/components/responses/Forbidden'
  
  /intellidog/feeds/{feed_id}:
    parameters:
      - $ref: '#/components/parameters/FeedId'
    
    get:
      tags: [Feeds]
      summary: Get feed details
      description: Retrieve detailed information about specific feed
      operationId: getFeed
      responses:
        '200':
          description: Feed details
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/FeedDetail'
        '404':
          $ref: '#/components/responses/NotFound'
    
    put:
      tags: [Feeds]
      summary: Update feed
      description: Update feed configuration
      operationId: updateFeed
      security:
        - BearerAuth: [admin]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/FeedUpdate'
      responses:
        '200':
          description: Feed updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
        '403':
          $ref: '#/components/responses/Forbidden'
    
    delete:
      tags: [Feeds]
      summary: Delete feed
      description: Delete feed and all associated IOCs
      operationId: deleteFeed
      security:
        - BearerAuth: [admin]
      responses:
        '200':
          description: Feed deleted successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
        '403':
          $ref: '#/components/responses/Forbidden'
  
  /intellidog/feeds/update:
    post:
      tags: [Feeds]
      summary: Trigger feed update
      description: Manually trigger feed update (bypasses schedule)
      operationId: triggerFeedUpdate
      security:
        - BearerAuth: [admin]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                feed_ids:
                  type: array
                  items:
                    type: integer
                  description: Specific feed IDs to update (empty = all)
                force:
                  type: boolean
                  default: true
      responses:
        '202':
          description: Feed update task queued
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          task_id:
                            type: string
                          feeds_count:
                            type: integer
  
  /intellidog/feeds/{feed_id}/test:
    parameters:
      - $ref: '#/components/parameters/FeedId'
    
    post:
      tags: [Feeds]
      summary: Test feed connection
      description: Test connectivity and authentication to feed source
      operationId: testFeed
      responses:
        '200':
          description: Connection test result
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          success:
                            type: boolean
                          message:
                            type: string
  
  # ========================================================================
  # IOC ENDPOINTS
  # ========================================================================
  /intellidog/iocs:
    get:
      tags: [IOCs]
      summary: List IOCs
      description: Search and browse Indicators of Compromise
      operationId: listIOCs
      parameters:
        - name: ioc_type
          in: query
          schema:
            $ref: '#/components/schemas/IOCType'
        - name: severity
          in: query
          schema:
            $ref: '#/components/schemas/Severity'
        - name: threat_type
          in: query
          schema:
            type: string
        - name: feed_id
          in: query
          schema:
            type: integer
        - name: is_active
          in: query
          schema:
            type: boolean
        - name: whitelisted
          in: query
          schema:
            type: boolean
        - name: search
          in: query
          schema:
            type: string
          description: Search in value/description
        - name: tags
          in: query
          schema:
            type: string
          description: Comma-separated tags
        - name: from_date
          in: query
          schema:
            type: string
            format: date-time
        - name: to_date
          in: query
          schema:
            type: string
            format: date-time
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/PerPage'
      responses:
        '200':
          description: List of IOCs
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          iocs:
                            type: array
                            items:
                              $ref: '#/components/schemas/IOC'
                          pagination:
                            $ref: '#/components/schemas/Pagination'
  
  /intellidog/iocs/{ioc_id}:
    parameters:
      - $ref: '#/components/parameters/IOCId'
    
    get:
      tags: [IOCs]
      summary: Get IOC details
      description: Retrieve detailed IOC information
      operationId: getIOC
      responses:
        '200':
          description: IOC details
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/IOCDetail'
  
  /intellidog/iocs/{ioc_id}/whitelist:
    parameters:
      - $ref: '#/components/parameters/IOCId'
    
    post:
      tags: [IOCs]
      summary: Whitelist IOC
      description: Mark IOC as false positive
      operationId: whitelistIOC
      security:
        - BearerAuth: [admin, team_leader]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [whitelist_reason]
              properties:
                whitelist_reason:
                  type: string
                  maxLength: 500
      responses:
        '200':
          description: IOC whitelisted successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
  
  # ========================================================================
  # DETECTION ENDPOINTS
  # ========================================================================
  /intellidog/detections:
    get:
      tags: [Detections]
      summary: List detections
      description: Retrieve threat detections with filters
      operationId: listDetections
      parameters:
        - name: machine_id
          in: query
          schema:
            type: integer
        - name: status
          in: query
          schema:
            $ref: '#/components/schemas/DetectionStatus'
        - name: severity
          in: query
          schema:
            $ref: '#/components/schemas/Severity'
        - name: detection_type
          in: query
          schema:
            $ref: '#/components/schemas/DetectionType'
        - name: assigned_to
          in: query
          schema:
            type: integer
        - name: from_date
          in: query
          schema:
            type: string
            format: date-time
        - name: to_date
          in: query
          schema:
            type: string
            format: date-time
        - name: false_positive
          in: query
          schema:
            type: boolean
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/PerPage'
      responses:
        '200':
          description: List of detections
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          detections:
                            type: array
                            items:
                              $ref: '#/components/schemas/Detection'
                          pagination:
                            $ref: '#/components/schemas/Pagination'
  
  /intellidog/detections/{detection_id}:
    parameters:
      - $ref: '#/components/parameters/DetectionId'
    
    get:
      tags: [Detections]
      summary: Get detection details
      description: Retrieve full detection information
      operationId: getDetection
      responses:
        '200':
          description: Detection details
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/DetectionDetail'
  
  /intellidog/detections/{detection_id}/acknowledge:
    parameters:
      - $ref: '#/components/parameters/DetectionId'
    
    post:
      tags: [Detections]
      summary: Acknowledge detection
      description: Mark detection as acknowledged
      operationId: acknowledgeDetection
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                notes:
                  type: string
                  maxLength: 1000
      responses:
        '200':
          description: Detection acknowledged
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
  
  /intellidog/detections/{detection_id}/resolve:
    parameters:
      - $ref: '#/components/parameters/DetectionId'
    
    post:
      tags: [Detections]
      summary: Resolve detection
      description: Mark detection as resolved
      operationId: resolveDetection
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [resolution_action]
              properties:
                resolution_action:
                  type: string
                  maxLength: 1000
                false_positive:
                  type: boolean
                  default: false
      responses:
        '200':
          description: Detection resolved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
  
  # ========================================================================
  # VIRTUAL PATCH ENDPOINTS
  # ========================================================================
  /intellidog/virtual-patches:
    get:
      tags: [Virtual Patches]
      summary: List virtual patches
      description: Retrieve auto-generated virtual patches
      operationId: listVirtualPatches
      parameters:
        - name: status
          in: query
          schema:
            $ref: '#/components/schemas/VirtualPatchStatus'
        - name: severity
          in: query
          schema:
            $ref: '#/components/schemas/Severity'
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/PerPage'
      responses:
        '200':
          description: List of virtual patches
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          patches:
                            type: array
                            items:
                              $ref: '#/components/schemas/VirtualPatch'
                          pagination:
                            $ref: '#/components/schemas/Pagination'
  
  /intellidog/virtual-patches/{patch_id}:
    parameters:
      - $ref: '#/components/parameters/PatchId'
    
    get:
      tags: [Virtual Patches]
      summary: Get virtual patch details
      operationId: getVirtualPatch
      responses:
        '200':
          description: Virtual patch details
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        $ref: '#/components/schemas/VirtualPatchDetail'
    
    delete:
      tags: [Virtual Patches]
      summary: Remove virtual patch
      description: Remove deployed patch (delete firewall rules)
      operationId: removeVirtualPatch
      security:
        - BearerAuth: [admin, team_leader]
      responses:
        '200':
          description: Patch removed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'
  
  /intellidog/virtual-patches/{patch_id}/approve:
    parameters:
      - $ref: '#/components/parameters/PatchId'
    
    post:
      tags: [Virtual Patches]
      summary: Approve virtual patch
      description: Approve and deploy patch to Firedog
      operationId: approveVirtualPatch
      security:
        - BearerAuth: [admin, team_leader]
      responses:
        '200':
          description: Patch deployed successfully
          content:
            application/json:
              schema:
                allOf:
                  - $ref: '#/components/schemas/SuccessResponse'
                  - type: object
                    properties:
                      data:
                        type: object
                        properties:
                          status:
                            type: string
                            enum: [deployed]
                          deployment_result:
                            type: object
  
  /intellidog/virtual-patches/{patch_id}/reject:
    parameters:
      - $ref: '#/components/parameters/PatchId'
    
    post:
      tags: [Virtual Patches]
      summary: Reject virtual patch
      description: Reject pending patch
      operationId: rejectVirtualPatch
      security:
        - BearerAuth: [admin, team_leader]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                reason:
                  type: string
                  maxLength: 500
      responses:
        '200':
          description: Patch rejected
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'

# ========================================================================
# COMPONENTS
# ========================================================================
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT token obtained from CyberSheppard authentication
  
  parameters:
    FeedId:
      name: feed_id
      in: path
      required: true
      schema:
        type: integer
      description: Feed ID
    
    IOCId:
      name: ioc_id
      in: path
      required: true
      schema:
        type: integer
      description: IOC ID
    
    DetectionId:
      name: detection_id
      in: path
      required: true
      schema:
        type: integer
      description: Detection ID
    
    PatchId:
      name: patch_id
      in: path
      required: true
      schema:
        type: integer
      description: Virtual patch ID
    
    Page:
      name: page
      in: query
      schema:
        type: integer
        default: 1
        minimum: 1
      description: Page number
    
    PerPage:
      name: per_page
      in: query
      schema:
        type: integer
        default: 20
        minimum: 1
        maximum: 100
      description: Items per page
  
  responses:
    Unauthorized:
      description: Unauthorized - Invalid or missing JWT token
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
    
    Forbidden:
      description: Forbidden - Insufficient permissions
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
    
    NotFound:
      description: Resource not found
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
    
    ValidationError:
      description: Validation error
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
  
  schemas:
    # Base Responses
    SuccessResponse:
      type: object
      required: [success]
      properties:
        success:
          type: boolean
          enum: [true]
        message:
          type: string
    
    ErrorResponse:
      type: object
      required: [success, error]
      properties:
        success:
          type: boolean
          enum: [false]
        error:
          type: object
          required: [code, message]
          properties:
            code:
              type: string
            message:
              type: string
            details:
              type: object
        timestamp:
          type: string
          format: date-time
        request_id:
          type: string
    
    Pagination:
      type: object
      required: [page, per_page, total, pages]
      properties:
        page:
          type: integer
        per_page:
          type: integer
        total:
          type: integer
        pages:
          type: integer
    
    # Enums
    FeedType:
      type: string
      enum: [misp, otx, stix, taxii, custom, csv, json]
    
    IOCType:
      type: string
      enum:
        - ip
        - domain
        - url
        - email
        - hash_md5
        - hash_sha1
        - hash_sha256
        - cve
        - registry_key
        - file_path
        - user_agent
        - ssl_cert_fingerprint
        - bitcoin_address
        - mutex
        - yara_rule
    
    Severity:
      type: string
      enum: [critical, high, medium, low, info]
    
    TLPLevel:
      type: string
      enum: [red, amber, green, white]
      description: Traffic Light Protocol level
    
    DetectionType:
      type: string
      enum:
        - firewall_match
        - vuln_correlation
        - behavioral_anomaly
        - threat_hunting_hit
        - feed_match
        - pattern_match
        - exploit_attempt
    
    DetectionStatus:
      type: string
      enum: [new, acknowledged, investigating, resolved, false_positive, escalated, suppressed]
    
    VirtualPatchStatus:
      type: string
      enum: [pending, approved, deployed, failed, rejected, removed]
    
    # License
    License:
      type: object
      properties:
        id:
          type: integer
        license_key:
          type: string
          example: "INTL-2025-ACME-0001"
        customer:
          type: string
        issued_at:
          type: string
          format: date-time
        expires_at:
          type: string
          format: date-time
          nullable: true
        max_machines:
          type: integer
        features:
          type: array
          items:
            type: string
        support_level:
          type: string
          enum: [standard, professional, enterprise]
        is_active:
          type: boolean
        last_validated_at:
          type: string
          format: date-time
          nullable: true
        days_until_expiry:
          type: integer
          nullable: true
    
    # Feed
    Feed:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        feed_type:
          $ref: '#/components/schemas/FeedType'
        url:
          type: string
          format: uri
          nullable: true
        description:
          type: string
          nullable: true
        is_active:
          type: boolean
        auto_update:
          type: boolean
        update_interval_minutes:
          type: integer
        last_update_at:
          type: string
          format: date-time
          nullable: true
        last_update_success:
          type: boolean
          nullable: true
        next_update_at:
          type: string
          format: date-time
          nullable: true
        ioc_count:
          type: integer
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time
    
    FeedDetail:
      allOf:
        - $ref: '#/components/schemas/Feed'
        - type: object
          properties:
            last_update_error:
              type: string
              nullable: true
            update_history:
              type: array
              items:
                type: object
                properties:
                  timestamp:
                    type: string
                    format: date-time
                  success:
                    type: boolean
                  iocs_added:
                    type: integer
                  iocs_updated:
                    type: integer
                  duration_ms:
                    type: integer
    
    FeedCreate:
      type: object
      required: [name, feed_type]
      properties:
        name:
          type: string
          maxLength: 100
        feed_type:
          $ref: '#/components/schemas/FeedType'
        url:
          type: string
          format: uri
        description:
          type: string
        is_active:
          type: boolean
          default: true
        auto_update:
          type: boolean
          default: true
        update_interval_minutes:
          type: integer
          minimum: 5
          default: 60
        api_key:
          type: string
        additional_config:
          type: object
    
    FeedUpdate:
      type: object
      properties:
        name:
          type: string
        url:
          type: string
          format: uri
        description:
          type: string
        is_active:
          type: boolean
        auto_update:
          type: boolean
        update_interval_minutes:
          type: integer
    
    # IOC
    IOC:
      type: object
      properties:
        id:
          type: integer
        feed_id:
          type: integer
        ioc_type:
          $ref: '#/components/schemas/IOCType'
        value:
          type: string
        severity:
          $ref: '#/components/schemas/Severity'
        confidence_score:
          type: integer
          minimum: 0
          maximum: 100
        threat_type:
          type: string
          nullable: true
        threat_category:
          type: string
          nullable: true
        description:
          type: string
          nullable: true
        tags:
          type: array
          items:
            type: string
        first_seen:
          type: string
          format: date-time
        last_seen:
          type: string
          format: date-time
        expiration_date:
          type: string
          format: date-time
          nullable: true
        is_active:
          type: boolean
        false_positive:
          type: boolean
        whitelisted:
          type: boolean
        tlp_level:
          $ref: '#/components/schemas/TLPLevel'
        source_reference:
          type: string
          nullable: true
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time
    
    IOCDetail:
      allOf:
        - $ref: '#/components/schemas/IOC'
        - type: object
          properties:
            feed_name:
              type: string
            whitelist_reason:
              type: string
              nullable: true
            metadata:
              type: object
            related_detections:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  title:
                    type: string
                  severity:
                    $ref: '#/components/schemas/Severity'
                  detected_at:
                    type: string
                    format: date-time
    
    # Detection
    Detection:
      type: object
      properties:
        id:
          type: integer
        machine_id:
          type: integer
        ioc_id:
          type: integer
          nullable: true
        detection_type:
          $ref: '#/components/schemas/DetectionType'
        severity:
          $ref: '#/components/schemas/Severity'
        confidence_score:
          type: integer
        title:
          type: string
        description:
          type: string
          nullable: true
        status:
          $ref: '#/components/schemas/DetectionStatus'
        risk_score:
          type: integer
          nullable: true
        auto_patched:
          type: boolean
        virtual_patch_id:
          type: integer
          nullable: true
        assigned_to:
          type: integer
          nullable: true
        detected_at:
          type: string
          format: date-time
        created_at:
          type: string
          format: date-time
        machine:
          type: object
          properties:
            id:
              type: integer
            hostname:
              type: string
            ip_address:
              type: string
        ioc:
          type: object
          nullable: true
          properties:
            id:
              type: integer
            ioc_type:
              $ref: '#/components/schemas/IOCType'
            value:
              type: string
            severity:
              $ref: '#/components/schemas/Severity'
    
    DetectionDetail:
      allOf:
        - $ref: '#/components/schemas/Detection'
        - type: object
          properties:
            source_data:
              type: object
            correlation_context:
              type: object
            notes:
              type: string
              nullable: true
            false_positive:
              type: boolean
            acknowledged_at:
              type: string
              format: date-time
              nullable: true
            resolved_at:
              type: string
              format: date-time
              nullable: true
            resolution_action:
              type: string
              nullable: true
    
    # Virtual Patch
    VirtualPatch:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        description:
          type: string
        patch_type:
          type: string
          enum: [block_ip, block_port, block_domain, rate_limit, geo_block, protocol_block, signature_block]
        severity:
          $ref: '#/components/schemas/Severity'
        ioc_id:
          type: integer
          nullable: true
        detection_id:
          type: integer
          nullable: true
        firewall_rule_template:
          type: object
        target_machines:
          type: array
          items:
            type: integer
        target_all_machines:
          type: boolean
        status:
          $ref: '#/components/schemas/VirtualPatchStatus'
        auto_approve:
          type: boolean
        approval_required:
          type: boolean
        approved_by:
          type: integer
          nullable: true
        approved_at:
          type: string
          format: date-time
          nullable: true
        deployed_at:
          type: string
          format: date-time
          nullable: true
        expires_at:
          type: string
          format: date-time
          nullable: true
        auto_remove_on_expiry:
          type: boolean
        created_at:
          type: string
          format: date-time
    
    VirtualPatchDetail:
      allOf:
        - $ref: '#/components/schemas/VirtualPatch'
        - type: object
          properties:
            deployment_result:
              type: object
              nullable: true
            removed_at:
              type: string
              format: date-time
              nullable: true
            removed_by:
              type: integer
              nullable: true
            ioc:
              type: object
              nullable: true
            detection:
              type: object
              nullable: true
```

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
