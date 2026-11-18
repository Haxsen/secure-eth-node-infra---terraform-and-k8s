# -----------------------------------------------------------------------------
# AWS WAFv2 web ACL attached to the public RPC ALB (via Ingress annotation).
#
# Layer 1 of the RPC DDoS defence (layer 2 = gateway per-key/per-IP limits,
# layer 3 = geth --rpc.* resource caps, layer 4 = NetworkPolicy isolation):
#   - AWS IP reputation list (botnets, scanners)
#   - Known-bad-inputs (Log4Shell & friends)
#   - Per-source-IP rate-based rule, evaluated over a 60s window
#   - Optional geo block (sanctions compliance is a real requirement for
#     many Web3 operators)
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name}-rpc"
  description = "Edge protection for the public Ethereum JSON-RPC endpoint"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  custom_response_body {
    key          = "rate_limited"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({ jsonrpc = "2.0", id = null, error = { code = -32005, message = "rate limit exceeded" } })
  }

  custom_response_body {
    key          = "blocked"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({ jsonrpc = "2.0", id = null, error = { code = -32000, message = "request blocked" } })
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 0

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = length(var.blocked_country_codes) > 0 ? [1] : []
    content {
      name     = "geo-block"
      priority = 5

      action {
        block {
          custom_response {
            response_code            = 403
            custom_response_body_key = "blocked"
          }
        }
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_country_codes
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-geo-block"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 10

    action {
      block {
        custom_response {
          response_code            = 429
          custom_response_body_key = "rate_limited"
        }
      }
    }

    statement {
      rate_based_statement {
        aggregate_key_type    = "IP"
        limit                 = var.rate_limit_per_ip
        evaluation_window_sec = 60
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit-per-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-rpc"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# WAF requires the log group name to start with "aws-waf-logs-".
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name}-rpc"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  # Never write customer API keys into logs.
  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }
}
